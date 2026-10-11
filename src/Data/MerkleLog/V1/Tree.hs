{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.V1.Tree
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- NOTE: this module provides the legacy API for merkle logs. It uses the V1
-- version of the proof format. If backward compatibility is not required the
-- use of the new API and the V2 proof format from the module "Data.MerkleLog"
-- is recommended.
--
-- Merkle Logs are an append-only data structure. The tree layout in this
-- implementation of Merkle trees is based on the description of Merkle trees in
-- RFC 6962. With this tree layout extending a Merkle tree requires chaining a
-- logarithmic number of nodes at the end of the tree. Unlike RFC 6962 the
-- Merkle trees in this module support the creation of unbalanced MerkleTrees by
-- nesting sub-trees as leafs of Merkle trees. Also, unlike RFC 6962 this module
-- generates fully self-contained inclusion proofs that don't rely on the client
-- being aware of the balancing of the Merkle Tree that was used to generate the
-- proof.
--
-- = Example
--
-- @
-- {-\# LANGUAGE TypeApplications #-}
-- {-\# LANGUAGE OverloadedStrings #-}
--
-- import qualified Data.ByteString as B
-- import Data.Hash.SHA2 (Sha2_256)
--
-- inputs = InputNode <$> ["a", "b", "c"] :: [MerkleNodeType Sha2_256]
--
-- -- create tree
-- t = merkleTree @SHA512t_256 inputs
--
-- -- create inclusion proof
-- p = either (error . show) id $ merkleProof 1 (inputs !! 1) t
--
-- -- verify proof
-- runMerkleProof p == merkleRoot t
-- @
--
module Data.MerkleLog.V1.Tree
(
-- * Merkle Tree
  MerkleTree
, decodeMerkleTree
, emptyMerkleTree
, encodeMerkleTree
, isEmpty
, leafCount
, merkleTree
, merkleTreeProof
, merkleTreeProof_
, merkleTreeRoot
, size
) where

import Control.DeepSeq (NFData)
import Control.Monad.Catch
import Data.Array.Byte
import Data.ByteString qualified as B
import Data.Foldable
import Data.Hash.Class.Mutable
import Data.List.NonEmpty qualified as NE
import Data.MerkleLog.Internal
import Data.MerkleLog.Utils
import Data.MerkleLog.V1.Primitive
import Data.MerkleLog.V1.Proof
import Data.MerkleLog.V1.Slice
import Data.Word
import GHC.Exts (indexWord32Array#)
import GHC.Generics (Generic)
import GHC.Stack
import GHC.Word
import Unsafe.Coerce
import Data.Coerce

-- -------------------------------------------------------------------------- --
-- Merkle Tree

-- | Binary Merkle Tree.
--
-- A Merkle Tree is only an index. It doesn't store any data but only hashes of
-- the data that is referenced in the tree.
--
newtype MerkleTree a = MerkleTree ByteArray
    deriving (Eq, Generic)
    deriving newtype (NFData)
    deriving (Show) via Base64Encoded

-- | Merkle Tree as described in RFC 6962, but with a configurable hash function
-- and support for nested Merkle trees.
--
-- The Merkle tree for the empty input log is the hash of the empty string.
--
-- This function is rarely needed. Computing the full tree is beneficial only
-- for very large trees when it pays of to cache and possibly persist the tree
-- or if you need to compute several proofs for different leafs. Otherwise it is
-- more efficient to compute the root or the proof directly from the inputs. (If
-- you need both a proof and the root, first compute the proof and than run the
-- proof to get the root.)
--
-- Note that the length of the list is forced before the algorithm starts
-- processing the items.
--
merkleTree
    :: forall a
    . HasCallStack
    => MerkleHashAlgorithm a
    => [MerkleNodeType a]
    -> MerkleTree a
merkleTree [] = MerkleTree $ nullHashBytes @a

-- Would it be better to use (nonDupable) unsafePerfromIO here? I guess it
-- depends on the expected size of the tree. Experience shows that taking the
-- lock for unsafePerformIO is often more expensive than simple computations
-- that do not involve IO.
--
merkleTree !items = MerkleTree $ createByteArray (treeSize * hs) $ \arr -> do
    !ctx <- initialize @a
    let
        -- | This uses logarithmic stack space
        --
        go
            :: Int
                -- ^ offset in the output tree
            -> [MerkleNodeType a]
                -- ^ input log
            -> [(Int, Int)]
                -- stack of tree hight and offset in the tree
                -- FIXME compute offset and hight from the input index
                -- (Would that be actullay faster? Maybe storing is better?)
            -> IO ()

        -- Create new inner node from stack tree positions on stack
        --
        go !i t ((!a, !ia) : (!b, !ib) : s) | a == b = do
            merkleNode_ @a ctx
                (mutableSliceN ib arr)
                (mutableSliceN ia arr)
                (mutableSliceN i arr)
            go (i + hs) t ((a + 1, i) : s)

        -- Create new leaf node on the stack
        --
        go !i (InputNode h : t) !s = do
            merkleLeaf_ @a ctx h (mutableSliceN i arr)
            go (i + hs) t ((0, i) : s)

        go !i (TreeNode h : t) !s = do
            copySliceN (unsafeSliceN @(DigestSize a) (coerce h)) (mutableSliceN i arr)
            go (i + hs) t ((0, i) : s)

        -- When all inputs are consumed, include remaining nodes on the
        -- stack as unbalanced subtree
        --
        go !i [] ((!a, !ia) : (!_, !ib) : s) = do
            merkleNode_ @a ctx
                (mutableSliceN ib arr)
                (mutableSliceN ia arr)
                (mutableSliceN i arr)
            go (i + hs) [] ((a + 1, i) : s)

        go _ [] [_] = return ()

        go _ [] [] = error "code invariant violation"

    go 0 items []
  where
    treeSize = 2 * (length items) - 1
    hs = hashSize @a

-- | Test a Merkle tree is the tree of the empty log.
--
isEmpty
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleTree a
    -> Bool
isEmpty = (==) (emptyMerkleTree @a)
{-# INLINE isEmpty #-}

-- | The Merkle tree of the empty log. RFC 6962 specifies that this is the hash
-- of the empty string.
--
emptyMerkleTree
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleTree a
emptyMerkleTree = merkleTree @a ([] @(MerkleNodeType a))
{-# INLINEABLE emptyMerkleTree #-}

-- | Binary encoding of a Merkle tree.
--
encodeMerkleTree :: MerkleTree a -> B.ByteString
encodeMerkleTree (MerkleTree b) = fromByteArray b
{-# INLINE encodeMerkleTree #-}

-- | The number of nodes (including leafs) in a Merkle tree.
--
size
    :: forall a
    . IncrementalHash a
    => MerkleTree a
    -> Int
size (MerkleTree arr) = byteArraySize arr `div` hashSize @a
{-# INLINE size #-}

-- | Decode are Merkle tree from a binary representation.
--
decodeMerkleTree
    :: forall a m
    . MonadThrow m
    => IncrementalHash a
    => B.ByteString
    -> m (MerkleTree a)
decodeMerkleTree b
    | B.length b `mod` hashSize @a == 0 = return $ MerkleTree $ toByteArray b
    | otherwise = throwM $ EncodingSizeConstraintException
        "MerkleTree"
        (Expected $ "multiple of " <> sshow (hashSize @a @Int))
        (Actual $ B.length b)
{-# INLINE decodeMerkleTree #-}

-- | Get the root of Merkle tree.
--
merkleTreeRoot
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleTree a
    -> MerkleRoot a
merkleTreeRoot t = getHash t (size t - 1)
{-# INLINE merkleTreeRoot #-}

-- -------------------------------------------------------------------------- --
-- Proof Extraction

-- | Extract a self-contained Merkle inclusion proof from a Merkle Tree
--
-- Usually it is much faster to create the proof directly from the inputs
-- without building the full tree first.
--
merkleTreeProof
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => MerkleNodeType a
    -> Int
    -> MerkleTree a
    -> m (MerkleProof a)
merkleTreeProof a pos t
    | pos < 0 || pos >= leafCount t = throwM $ IndexOutOfBoundsException
        "merkleProof"
        (Expected (0,leafCount t - 1))
        (Actual pos)
    | treeSlice t tpos /= unsafeSliceN (coerce $ merkleLeaf @a a) =
        throwM $ inputNotInTreeException "merkleProof" pos a
    | otherwise = return $ MerkleProof
        { _merkleProofSubject = MerkleProofSubject a
        , _merkleProofObject = MerkleProofObject go
        }
  where
    (tpos, path) = proofPath pos (leafCount t)

    go = createByteArray (proofObjectSizeInBytes @a (length path)) $ \arr -> do
        write32Be arr 0 (length path)
        write64Be arr 4 pos
        go2 arr (path `zip` [0, int (stepSize @a) ..])

    go2 _ [] = return ()
    go2 arr (((z, i), x): r) = do
        write8 arr (12 + x) (sideWord8 z)
        copySliceN (treeSlice t i) (mutableSliceN (13 + x) arr)
        go2 arr r

-- | Extract a Merkle proof for a proof subject in a nested sub-tree.
--
-- Note that it is generally more efficient to construct the individual proofs
-- directly using the functions in "Data.MerkleLog.Proof.V2" and concatenate the
-- results using the 'Semigroup' instance for proofs.
--
merkleTreeProof_
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => MerkleNodeType a
        -- ^ The proof subject
    -> NE.NonEmpty (Int, MerkleTree a)
        -- ^ The proof components
    -> m (MerkleProof a)
merkleTreeProof_ a l = MerkleProof
    <$> pure (MerkleProofSubject a)
    <*> (MerkleProofObject <$> mkObject)
  where
    mkObject = go2 <$> go a (NE.toList l)

    -- position of the output subject
    fstPos = fst $ NE.head l

    -- Stepsize
    ss = stepSize @a

    go _ [] = return []
    go sub ((pos, tree) : t) = do
        -- create sub-proof
        MerkleProof (MerkleProofSubject _) (MerkleProofObject o) <- merkleTreeProof sub pos tree
        -- collect step counts and stripped proof objects
        (:) (extractSteps o) <$> go (TreeNode $ merkleTreeRoot tree) t

    -- extract path length from proof
    --
    -- FIXME this is should be the same as @div# (sizeOfByteArray# arr# -# 12#)
    -- (hashSize# @a + 1)@ We could double check when we traverse later on.
    --
    extractSteps :: ByteArray -> (Int, ByteArray)
    extractSteps arr@(ByteArray arr#) = (steps, arr)
      where
        steps = int $ be32 (W32# $ indexWord32Array# arr# 0#)

    -- create output proof
    go2 ps = createByteArray len $ \arr -> do
        write32Be arr 0 steps
        write64Be arr 4 (be32 $ int $ fstPos)
        go3 arr (toList ps) 0
      where
        steps = sum $ fst <$> ps
        len = 12 + steps * ss

    -- Copy sub-proofs into the output proof object
    go3 _ [] _ = return ()
    go3 arr ((n, o):t) i = do
        copyByteArray o 12 arr (12 + i * ss) (n * ss)
        go3 arr t (i + n)

-- --------------------------------------------------------------------------
-- Utils

-- | Get the hash of a node in the Merkle tree.
--
getHash
    :: MerkleHashAlgorithm a
    => MerkleTree a
    -> Int
    -> MerkleRoot a
getHash t = MerkleRoot . getSliceN . treeSlice t
{-# INLINE getHash #-}

sideWord8 :: Side -> Word8
sideWord8 L = 0x00
sideWord8 R = 0x01
{-# INLINE sideWord8 #-}

-- | Get the number of leafs in a Merkle tree.
--
leafCount
    :: MerkleHashAlgorithm a
    => MerkleTree a
    -> Int
leafCount t
    | isEmpty t = 0
    | otherwise = 1 + size t `div` 2
{-# INLINE leafCount #-}

treeSlice
    :: forall a
    . IncrementalHash a
    => MerkleTree a
    -> Int
    -> HashSlice a
treeSlice (MerkleTree !(ByteArray v)) i = SliceN (unI# (i * hashSize @a)) v
{-# INLINE treeSlice #-}

-- -------------------------------------------------------------------------- --
-- Hash Computations

merkleNode_
    :: forall a
    . IncrementalHash a
    => ResetableHash a
    => Context a
    -> MutableHashSlice a
    -> MutableHashSlice a
    -> MutableHashSlice a
    -> IO ()
merkleNode_ ctx a b r = do
    reset @a ctx
    updateByteArray @a ctx nodeTag

    -- This is based on the assumption that ByteArray and MutableByteArray
    -- have the same heap representation.
    updateHashSlice @a ctx (unsafeCoerce a)
    updateHashSlice @a ctx (unsafeCoerce b)
    finalizeHashSlice @a ctx r

-- | Compute hash for a leaf node in a Merkle tree.
--
merkleLeaf_
    :: forall a
    . IncrementalHash a
    => ResetableHash a
    => Context a
    -> B.ByteString
    -> MutableHashSlice a
    -> IO ()
merkleLeaf_ ctx b r = do
    reset @a ctx
    updateByteArray @a ctx $ leafTag
    updateByteString @a ctx b
    finalizeHashSlice @a ctx r

