{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.V1.Proof
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.V1.Proof
( MerkleProofObject(..)
, encodeMerkleProofObject
, decodeMerkleProofObject
, MerkleProofSubject(..)
, MerkleProof(..)
, runMerkleProof

-- * For internal use
, proofPath
, stepSize
, proofObjectSizeInBytes
, Side(..)
) where

import Control.DeepSeq (NFData)
import Control.Monad
import Control.Monad.Catch
import Data.Array.Byte
import Data.ByteString qualified as B
import Data.ByteString.Unsafe qualified as B
import Data.Hash.Class.Mutable
import Data.MerkleLog.Internal
import Data.MerkleLog.Utils
import Data.MerkleLog.V1.Primitive
import Data.MerkleLog.V1.Slice
import Data.Word
import Foreign (peek, castPtr)
import GHC.Generics (Generic)
import GHC.Num (integerLog2)
import System.IO.Unsafe
import Unsafe.Coerce
import Data.Coerce

-- -------------------------------------------------------------------------- --
-- Proof Object

-- | Opaque proof object.
--
newtype MerkleProofObject a = MerkleProofObject ByteArray
    deriving (Eq, Generic)
    deriving newtype (NFData)
    deriving (Show) via Base64Encoded

-- | Encode a Merkle proof object into binary format.
--
encodeMerkleProofObject :: MerkleProofObject a -> B.ByteString
encodeMerkleProofObject (MerkleProofObject b) = fromByteArray b
{-# INLINE encodeMerkleProofObject #-}

-- | Decode a Merkle proof object from a binary representation.
--
decodeMerkleProofObject
    :: forall a m
    . MonadThrow m
    => IncrementalHash a
    => B.ByteString
    -> m (MerkleProofObject a)
decodeMerkleProofObject b
    | B.length b < 12 = throwM
        $ EncodingSizeConstraintException
            "MerkleProofObject"
            (Expected "larger than 12")
            (Actual $ B.length b)
    | B.length b /= proofObjectSizeInBytes @a stepCount = throwM
        $ EncodingSizeException
            "MerkleProofObject"
            (Expected $ proofObjectSizeInBytes @a stepCount)
            (Actual $ B.length b)
    | otherwise = return $ MerkleProofObject $ toByteArray b
  where
    stepCount = peek32Be b

proofObjectSizeInBytes
    :: forall a
    . IncrementalHash a
    => Int
    -> Int
proofObjectSizeInBytes stepCount = stepSize @a * stepCount + 12
{-# INLINE proofObjectSizeInBytes #-}

-- -------------------------------------------------------------------------- --
-- Proof Subject

-- | The subject for which inclusion is proven.
--
newtype MerkleProofSubject a = MerkleProofSubject
    { _getMerkleProofSubject :: MerkleNodeType a }
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (NFData)

-- -------------------------------------------------------------------------- --

-- | Merkle Inclusion Proof. In RFC 6962 this is called an audit proof. The
-- proof in this module are not compatible with RFC 6962. They support proving
-- inclusion of subtrees and proof for unbalanced trees of unknown size.
--
-- The proof is self-contained. It is independent of the concrete implementation
-- of the Merkle tree. This type works with any binary Merkle tree type and
-- doesn't make any assumptions about the balancing of the tree.
--
-- The proof includes the subject of the proof (for which inclusion is proven)
-- as a plaintext bytestring. The proof does not include the root hash of the
-- Merkle tree, because the proof is only meaningful if the root is available
-- from a trusted source. Including it into the proof would thus be redundant or
-- even misleading.
--
-- A more compact encoding would use the first bit of each hash to encode the
-- side, but that would require to alter the hash computation. We also could
-- pack the sides into a bit array. However, the total number of bytes for the
-- sides will be most likely less than two hashes, so the overhead is small and
-- doesn't justify more clever encodings.
--
-- NOTE:
--
-- Note that the node 1 in the first tree and 2 and the second tree both share
-- the same trace and thus proof structure. Merkle proofs in the library do
-- therefore not generally carry evidence for the position of the subject in the
-- tree.
--
--                  *
--                /  \
--   *           *    \
--  / \         / \    \
-- 0   1  and  0   1    2
--
-- This observation also motivates the V2 proof format that omits the the
-- position from the proof, since it may be missleading.
--
-- It would still be possible to derive the (nonunique) trace from the position,
-- which would allow to ommit the explicit trace markers in the proof. However,
-- those markers cause little overhead (and performance overhead due to
-- non-optimial memory alignment is probably negligible, too). At the same time
-- those markers make it easy to create and verify proofs for nested trees.
--
data MerkleProof a = MerkleProof
    { _merkleProofSubject :: !(MerkleProofSubject a)
    , _merkleProofObject :: !(MerkleProofObject a)
    }
    deriving (Show, Eq, Generic)
    deriving anyclass (NFData)

-- -------------------------------------------------------------------------- --
-- Proof Verification

-- | Execute an inclusion proof. The result of the execution is a Merkle root
-- that must be compared to the trusted root of the Merkle tree.
--
runMerkleProof
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => MerkleProof a
    -> m (MerkleRoot a)
runMerkleProof p = MerkleRoot <$> runMerkleProofInternal @a subj obj
  where
    MerkleProofSubject subj = _merkleProofSubject p
    MerkleProofObject obj = _merkleProofObject p

runMerkleProofInternal
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => MerkleNodeType a
        -- ^ proof subject
    -> ByteArray
        -- ^ proof object
    -> m ByteArray
runMerkleProofInternal subj o
    | 12 + steps * stepSize @a /= objLen =
        throwM $ InvalidProofObjectException "runMerkleProofInternal"
    | otherwise = createByteArrayM (hashSize @a) $ \arr -> do
            ctx <- initialize @a
            let root = mutableSliceN 0 arr
            case subj of
                InputNode x -> merkleLeaf_ @a ctx x root
                TreeNode x -> copySliceN (unsafeSliceN @(DigestSize a) (coerce x)) root
            forM_ [0 .. steps - 1] $ \i -> do
                let off = 12 + i * stepSize @a
                case indexWord8Array o off of
                    0x00 -> merkleNode_ @a ctx (sliceN (off + 1) o) (unsafeCoerce root) root
                    0x01 -> merkleNode_ @a ctx (unsafeCoerce root) (sliceN (off + 1) o) root
                    _ -> throwM $ InvalidProofObjectException "runMerkleProofInternal"
  where
    steps = int $ be32 (indexWord32Array o 0)
    objLen = byteArraySize o

-- -------------------------------------------------------------------------- --
-- Proof Path

data Side = L | R
    deriving (Show, Eq)

-- | For a subject at a given position compute the path of the proof in the
-- tree.
--
proofPath
    :: Int
        -- ^ Position in log
    -> Int
        -- ^ Size of log
    -> (Int, [(Side, Int)])
        -- ^ The tree position of the target node and tree positions and
        -- directions of the audit proof.
proofPath b c = go 0 0 b c []
  where
    go _ !treeOff _ 1 !acc = (treeOff, acc)
    go !logOff !treeOff !m !n !acc
        | m < k = go logOff treeOff m k $ (R, treeOff + 2 * n - 3) : acc
        | otherwise = go (logOff + k) (treeOff + 2 * k - 1) (m - k) (n - k)
            $ (L, treeOff + 2 * k - 2) : acc
      where
        k = k2 n

-- -------------------------------------------------------------------------- --
-- utils

stepSize
    :: forall a
    . IncrementalHash a
    => Int
stepSize = hashSize @a + 1
{-# INLINE stepSize #-}

k2 :: Int -> Int
k2 i = 2 ^ integerLog2 (int i - 1)
{-# INLINE k2 #-}

-- | It is not checked that the ByteString is large enough
--
peek32Be :: Num n => B.ByteString -> n
peek32Be b = unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, _) ->
    int . be32 <$> peek @Word32 (castPtr ptr)
{-# INLINE peek32Be #-}

-- | Compute hash for inner node of a Merkle tree.
--
merkleNode_
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> HashSlice a
    -> HashSlice a
    -> MutableHashSlice a
    -> IO ()
merkleNode_ ctx a b r = do
    reset @a ctx
    updateByteArray @a ctx nodeTag
    updateHashSlice @a ctx a
    updateHashSlice @a ctx b
    finalizeHashSlice @a ctx r

-- | Compute hash for a leaf node in a Merkle tree.
--
merkleLeaf_
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> B.ByteString
    -> MutableHashSlice a
    -> IO ()
merkleLeaf_ ctx b r = do
    reset @a ctx
    updateByteArray @a ctx $ leafTag
    updateByteString @a ctx b
    finalizeHashSlice @a ctx r

