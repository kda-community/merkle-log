{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ConstraintKinds #-}

-- |
-- Module: Main
-- Copyright: Copyright © 2019 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Main
( main
) where

import Control.DeepSeq
import Control.Monad
import Control.Monad.Trans.State.Strict

import Criterion
import Criterion.Main

import Data.Hash.SHA2
import Data.Hash.SHA3
import Data.Hash.Blake2
import "cryptonite" Crypto.Hash qualified as CR

import Data.ByteArray qualified as BA
import Data.ByteString qualified as B
import Data.HashTree qualified as HT
import Data.Maybe

import GHC.Generics

import System.IO.Unsafe
import System.Random

import Streaming.Prelude qualified as S

-- internal modules

import Data.MerkleLog qualified as ML
import Data.MerkleLog.V1 qualified as MLV1
import Data.MerkleLog.NullHash

-- -------------------------------------------------------------------------- --
-- Main

main :: IO ()
main = defaultMain
    [ env (return globalEnv) $ \ ~e -> bgroup "main"
        [ bgroup "create tree"
            [ bgroup "SHA512t_256"
                [ createBench @(ML Sha2_512_256) e
                , createBench @(HT CR.SHA512t_256) e
                ]
            , bgroup "SHA256"
                [ createBench @(ML Sha2_256) e
                , createBench @(HT CR.SHA256) e
                ]
            , bgroup "SHA3_256"
                [ createBench @(ML Sha3_256) e
                , createBench @(HT CR.SHA3_256) e
                ]
            , bgroup "BLAKE2b_256"
                [ createBench @(ML Blake2s256) e
                ]
            ]
        , bgroup "create root"
            [ bgroup "SHA512t_256"
                [ rootBench @(ML Sha2_512_256) e
                ]
            , bgroup "SHA256"
                [ rootBench @(ML Sha2_256) e
                ]
            , bgroup "SHA3_256"
                [ rootBench @(ML Sha3_256) e
                ]
            , bgroup "BLAKE2b_256"
                [ rootBench @(ML Blake2s256) e
                ]
            ]
        , bgroup "create inclusion proof"
            [ bgroup "SHA512t_256"
                [ proofBench @(ML Sha2_512_256) e
                , proofBench @(HT CR.SHA512t_256) e
                ]
            , bgroup "SHA256"
                [ proofBench @(ML Sha2_256) e
                , proofBench @(HT CR.SHA256) e
                ]
            , bgroup "SHA3_256"
                [ proofBench @(ML Sha3_256) e
                , proofBench @(HT CR.SHA3_256) e
                ]
            , bgroup "BLAKE2s256"
                [ proofBench @(ML Blake2s256) e
                ]
            ]
        , bgroup "verify inclusion proof"
            [ bgroup "SHA512t_256"
                [ verifyBench @(ML Sha2_512_256) e
                , verifyBench @(HT CR.SHA512t_256) e
                ]
            , bgroup "SHA256"
                [ verifyBench @(ML Sha2_256) e
                , verifyBench @(HT CR.SHA256) e
                ]
            , bgroup "SHA3_256"
                [ verifyBench @(ML Sha3_256) e
                , verifyBench @(HT CR.SHA3_256) e
                ]
            , bgroup "BLAKE2s256"
                [ verifyBench @(ML Blake2s256) e
                ]
            ]
        ]
    , bgroup "root comparisions"
        [ bgroup "normalEnv"
            [ env (return globalRootEnv) $ \ ~e -> bgroup "NullHash"
                [ rootBench_treeRoot @(NullHash 32) e
                , rootBench_root @(NullHash 32) e
                , rootBench_rootIO @(NullHash 32) e
                , rootBench_rootStreaming @(NullHash 32) e
                ]
            , env (return globalRootEnv) $ \ ~e -> bgroup "Sha2_256"
                [ rootBench_treeRoot @(Sha2_256) e
                , rootBench_root @(Sha2_256) e
                , rootBench_rootIO @(Sha2_256) e
                , rootBench_rootStreaming @(Sha2_256) e
                ]
            ]
        , bgroup "smallBigEnv"
            [ env (return smallBigGlobalRootEnv) $ \ ~e -> bgroup "NullHash"
                [ rootBench_treeRoot @(NullHash 32) e
                , rootBench_root @(NullHash 32) e
                , rootBench_rootIO @(NullHash 32) e
                , rootBench_rootStreaming @(NullHash 32) e
                ]
            , env (return smallBigGlobalRootEnv) $ \ ~e -> bgroup "Sha2_256"
                [ rootBench_treeRoot @(Sha2_256) e
                , rootBench_root @(Sha2_256) e
                , rootBench_rootIO @(Sha2_256) e
                , rootBench_rootStreaming @(Sha2_256) e
                ]
            ]
        , bgroup "smallSmallEnv"
            [ env (return smallSmallGlobalRootEnv) $ \ ~e -> bgroup "NullHash"
                [ rootBench_treeRoot @(NullHash 32) e
                , rootBench_root @(NullHash 32) e
                , rootBench_rootIO @(NullHash 32) e
                , rootBench_rootStreaming @(NullHash 32) e
                ]
            , env (return smallBigGlobalRootEnv) $ \ ~e -> bgroup "Sha2_256"
                [ rootBench_treeRoot @(Sha2_256) e
                , rootBench_root @(Sha2_256) e
                , rootBench_rootIO @(Sha2_256) e
                , rootBench_rootStreaming @(Sha2_256) e
                ]
            ]
        ]
    ]

-- -------------------------------------------------------------------------- --
-- Merkle Tree Implementations
-- -------------------------------------------------------------------------- --

-- -------------------------------------------------------------------------- --
-- Global Environment

leafCount :: Int
leafCount = 10000
-- leafCount = 100

leafMaxSize :: Int
leafMaxSize = 1000
-- leafMaxSize = 8000

type GlobalEnv = [B.ByteString]

globalEnv :: GlobalEnv
globalEnv = evalState (replicateM leafCount genBytes) (mkStdGen 1)
  where
    genBytes = do
        len <- state $ randomR (0, leafMaxSize)
        state $ genByteString len

type GlobalRootEnv a = [ML.MerkleNodeType a]

globalRootEnv :: GlobalRootEnv a
globalRootEnv = evalState (replicateM leafCount genBytes) (mkStdGen 1)
  where
    genBytes = do
        len <- state $ randomR (0, leafMaxSize)
        ML.InputNode <$> state (genByteString len)

smallSmallGlobalRootEnv :: GlobalRootEnv a
smallSmallGlobalRootEnv = evalState (replicateM 30 genBytes) (mkStdGen 1)
  where
    genBytes = do
        len <- state $ randomR (0, 400)
        ML.InputNode <$> state (genByteString len)

smallBigGlobalRootEnv :: GlobalRootEnv a
smallBigGlobalRootEnv = evalState (replicateM 30 genBytes) (mkStdGen 1)
  where
    genBytes = do
        len <- state $ randomR (0, 8000)
        ML.InputNode <$> state (genByteString len)

-- -------------------------------------------------------------------------- --
-- Create Benchmark

createBench :: forall a . Impl a => GlobalEnv -> Benchmark
createBench = bench (label @a) . nf (tree @a)

-- -------------------------------------------------------------------------- --
-- Compute Root Benchmark

rootBench :: forall a . Impl a => GlobalEnv -> Benchmark
rootBench = bench (label @a) . nf (root @a)

-- compute full merkle tree
rootBench_treeRoot :: forall a . ML.MerkleHashAlgorithm a => GlobalRootEnv a -> Benchmark
rootBench_treeRoot = bench "tree-root" . nf (MLV1.merkleTreeRoot . MLV1.merkleTree @a)

rootBench_root :: forall a . ML.MerkleHashAlgorithm a => GlobalRootEnv a -> Benchmark
rootBench_root = bench "root" . nf (ML.merkleRoot @a)

-- IO with stack as lazy list
rootBench_rootIO :: forall a . ML.MerkleHashAlgorithm a => GlobalRootEnv a -> Benchmark
rootBench_rootIO = bench "root-io"
    . nf (ML.merkleRoot @a)

-- IO with stack as lazy list with monadic streaming API
rootBench_rootStreaming :: forall a . ML.MerkleHashAlgorithm a => GlobalRootEnv a -> Benchmark
rootBench_rootStreaming = bench "root-streaming"
    . nf (unsafeDupablePerformIO . ML.merkleRootStream @a . S.each)

-- -------------------------------------------------------------------------- --
-- Proof Benchmark

type ProofEnv a = (Tree a, B.ByteString, Int)

proofEnv :: forall a . Impl a => GlobalEnv -> IO (ProofEnv a)
proofEnv e = return (tree @a e, e !! 277, 277)

-- | Note that this also includes verification of the proof, because that's the
-- only way we can ensure that the resulting proofs are in normal form.
--
proofBench
    :: forall a
    . Impl a
    => GlobalEnv
    -> Benchmark
proofBench e = env (proofEnv @a e)
    $ bench (label @a) . nf (\(t, ix, i) -> proof @a t ix i)

-- -------------------------------------------------------------------------- --
-- Verify Benchmark

type VerifyEnv a = Proof a

verifyEnv :: forall a . Impl a => GlobalEnv -> IO (VerifyEnv a)
verifyEnv e = return $ proof @a (tree @a e) (e !! 277) 277

verifyBench
    :: forall a
    . Impl a
    => GlobalEnv
    -> Benchmark
verifyBench e = env (verifyEnv @a e) $ bench (label @a) . nf verifyThrow
  where
    verifyThrow p
        | verify @a p = ()
        | otherwise = error "benchmark failure"

-- -------------------------------------------------------------------------- --
-- Merkle Tree Implementations
-- -------------------------------------------------------------------------- --

-- -------------------------------------------------------------------------- --
-- Merkle Tree Implementation Class

class (NFData (Tree a), NFData (Root a), NFData (Proof a)) => Impl a where
    type Tree a
    type Proof a
    type Root a

    label :: String
    tree :: [B.ByteString] -> Tree a
    root :: [B.ByteString] -> Root a
    treeRoot :: Tree a -> Root a
    proof :: Tree a -> B.ByteString -> Int -> Proof a
    verify :: Proof a -> Bool

-- -------------------------------------------------------------------------- --
-- merkle-log

data MLProof a = MLProof
    {-# UNPACK #-} !(MLV1.MerkleProof a)
    {-# UNPACK #-} !(MLV1.MerkleRoot a)
        -- ^ Root of the Tree
    deriving (Generic)

instance NFData (MLProof a)

data ML a

instance ML.MerkleHashAlgorithm a => Impl (ML a) where
    type Tree (ML a) = MLV1.MerkleTree a
    type Proof (ML a) = MLProof a
    type Root (ML a) = ML.MerkleRoot a

    label = "merkle-log"
    tree = MLV1.merkleTree @a . fmap ML.InputNode
    treeRoot = MLV1.merkleTreeRoot @a
    root = ML.merkleRoot . fmap ML.InputNode
    proof t ix i =
        let p = case MLV1.merkleTreeProof (ML.InputNode ix) i t of
                Right x -> x
                Left e -> error $ "proof creation failed in benchmark: " <> show e
        in MLProof p (MLV1.merkleTreeRoot t)
    verify (MLProof p r) = MLV1.runMerkleProof p == Just r

    {-# INLINE label #-}
    {-# INLINE tree #-}
    {-# INLINE root #-}
    {-# INLINE treeRoot #-}
    {-# INLINE proof #-}
    {-# INLINE verify #-}

-- -------------------------------------------------------------------------- --
-- hash-tree package

data HTProof a = HTProof
    {-# UNPACK #-} !(HT.InclusionProof a)
    {-# UNPACK #-} !B.ByteString
        -- ^ Proof subject (leaf)
    {-# UNPACK #-} !(CR.Digest a)
        -- ^ Root of the Tree
    deriving (Generic)

instance NFData (HTProof a)

instance NFData (HT.MerkleHashTrees B.ByteString a) where
    rnf t = rnf $ HT.digest (HT.size t) t
    {-# INLINE rnf #-}

instance NFData (HT.InclusionProof a) where
    rnf p = rnf (HT.leafIndex p)
        `seq` rnf (HT.treeSize p)
        `seq` rnf (HT.inclusion p)
    {-# INLINE rnf #-}

data HT a

htSettings :: forall a . CR.HashAlgorithm a => HT.Settings B.ByteString a
htSettings = HT.defaultSettings
    { HT.hash0 = CR.hash @B.ByteString @a mempty
    , HT.hash1 = \x -> CR.hash @_ @a (B.singleton 0x00 `B.append` x)
    , HT.hash2 = \x y -> CR.hash @_ @a $ B.concat [B.singleton 0x01, BA.convert x, BA.convert y]
    }

instance (CR.HashAlgorithm a) => Impl (HT a) where
    type Tree (HT a) = HT.MerkleHashTrees B.ByteString a
    type Proof (HT a) = HTProof a
    type Root (HT a) = CR.Digest a

    label = "hash-tree"
    tree = HT.fromList htSettings
    root = error "treeRoot is not supported"
    treeRoot t = fromJust $ HT.digest (HT.size t) t
    proof t ix _ = HTProof
        (fromJust $ HT.generateInclusionProof (HT.hash1 (htSettings @a) ix) (HT.size t) t)
        ix
        (treeRoot @(HT a) t)
    verify (HTProof p subj r) = HT.verifyInclusionProof
        (htSettings @a) (HT.hash1 (htSettings @a) subj) r p

    {-# INLINE label #-}
    {-# INLINE tree #-}
    {-# INLINE root #-}
    {-# INLINE proof #-}
    {-# INLINE verify #-}

