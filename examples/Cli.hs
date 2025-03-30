{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Cli
-- Copyright: Copyright © 2024 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Main
( main
) where

import Data.Base16.Types
import Data.ByteString qualified as B
import Data.ByteString.Base16
import Data.ByteString.Char8 qualified as B8
import Data.ByteString.Lazy qualified as BL
import Data.ByteString.Lazy.Char8 qualified as BL8
import Data.Hash.SHA2
import Data.MerkleLog
import Data.MerkleLog.V1 qualified as V1
import Streaming.Prelude qualified as SP
import System.Environment

-- import Data.MerkleLog.NullHash

type Alg = Sha2_512_256
-- type Alg = NullHash 32

-- | Strictly read input and compute full tree.
--
-- Uses continuous memory for the tree that is preallocate at the beginning of
-- the operation (which requires to stricly read the input into memory).
--
--
treeRoot :: IO ()
treeRoot = do
    ls <- fmap InputNode . B8.lines <$> B.getContents
    putStrLn $ "leaf count: " <> show (length ls)
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot
        $ V1.merkleTreeRoot
        $ V1.merkleTree @Alg
        $ ls

-- | Purely computes the root from a lazy input list
--
-- Uses Haskell's list type as stack and reallocates the hash context for each
-- operation.
--
root :: IO ()
root = do
    ls <- fmap (InputNode . BL.toStrict) . BL8.lines <$> BL.getContents
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot
        $ merkleRoot @Alg
        $ ls

-- | Computes the root in IO from a lazy input list
--
-- Uses a shared hash context for all operations. Uses Haskell's list type as
-- stack
--
rootIO :: IO ()
rootIO = do
    ls <- fmap (InputNode . BL.toStrict) . BL8.lines <$> BL.getContents
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot
        $ merkleRoot @Alg
        $ ls

-- | Compute the root in IO from input stream that allows internleaving IO.
--
-- Uses a shared hash context for all operations. Uses Haskell's list type as
-- stack
--
rootStreaming :: IO ()
rootStreaming = do
    bs <- BL.getContents
    r <- merkleRootStream @Alg
        $ SP.map (InputNode . BL.toStrict)
        $ SP.each
        $ BL8.lines
        $ bs
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot r

proofV1 :: Int -> IO ()
proofV1 pos = do
    ls <- fmap BL.toStrict . BL8.lines <$> BL.getContents
    let subj = ls !! pos
    p <- V1.merkleTreeProof @Alg (InputNode subj) pos
        $ V1.merkleTree
        $ fmap InputNode
        $ ls
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ ls !! pos
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ V1.encodeMerkleProofObject
        $ V1._merkleProofObject p

runProofV1 :: IO ()
runProofV1 = do
    subj <- B8.getLine
    bs <- B8.getLine
    p <- V1.decodeMerkleProofObject @Alg bs
    r <- V1.runMerkleProof @Alg $ V1.MerkleProof
        { V1._merkleProofObject = p
        , V1._merkleProofSubject = V1.MerkleProofSubject $ InputNode subj
        }
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot
        $ r

proofV2 :: Int -> IO ()
proofV2 pos = do
    ls <- fmap (InputNode . BL.toStrict) . BL8.lines <$> BL.getContents
    proof <- merkleProof @Alg pos ls
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeProof
        $ proof

runProofV2 :: IO ()
runProofV2 = do
    bs <- decodeBase16Lenient
        . BL.toStrict
        . BL.drop 2
        <$> BL.getContents
    p <- decodeProof @Alg bs
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot
        $ runProof p

-- | Check Proof creation and verification without serializing the proof
--
checkV2 :: Int -> IO ()
checkV2 pos = do
    ls <- fmap (InputNode . BL.toStrict) . BL8.lines <$> BL.getContents
    proof <- merkleProof @Alg pos ls
    B8.putStrLn $ (<>) "0x"
        $ extractBase16
        $ encodeBase16'
        $ encodeMerkleRoot
        $ runProof proof

main :: IO ()
main = do
    getArgs >>= \case
        ["root"] -> root
        ["root-io"] -> rootIO
        ["root-streaming"] -> rootStreaming
        ["proof", n] -> proofV2 (read n)
        ["run-proof"] -> runProofV2
        ["check", n] -> checkV2 (read n)

        ["root-v1"] -> treeRoot
        ["proof-v1", n] -> proofV1 (read n)
        ["run-proof-v1"] -> runProofV1

        ["proof"] -> error "missing position argument for proof-v2"
        ["proof-v1"] -> error "missing position argument for proof-v1"

        [c] -> error $ "Unknown operation type: " <> c
        _ -> error "wrong number of arguments"

