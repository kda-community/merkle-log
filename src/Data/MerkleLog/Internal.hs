{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.Internal
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.Internal
(
-- * Exceptions
  Expected(..)
, Actual(..)
, MerkleTreeException(..)
, textMessage
, inputNotInTreeException

-- * Hash Algorithm
, MerkleHashAlgorithm(..)
, hashSize
, nullHash
, nullHashBytes

-- * Merkle Root
, MerkleRoot(..)
, merkleRootBytes
, merkleRootSize
, encodeMerkleRoot
, decodeMerkleRoot
, finalizeRoot

-- * MerkleNodeType
, MerkleNodeType(..)
, leafTag
, nodeTag
, merkleLeaf
, merkleLeafIO
, merkleNode
, merkleNodeIO
) where

import Control.DeepSeq (NFData)
import Control.Monad.Catch
import Data.Array.Byte
import Data.ByteString qualified as B
import Data.Coerce
import Data.Hash.Class.Mutable
import Data.Hash.Internal.OpenSSL
import Data.MerkleLog.Utils
import Data.Text qualified as T
import GHC.Generics (Generic)
import GHC.TypeNats (KnownNat)
import System.IO.Unsafe

-- -------------------------------------------------------------------------- --
-- Exceptions

-- | An expected value.
--
newtype Expected a = Expected a
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (NFData)

-- | An actual value.
--
newtype Actual a = Actual a
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (NFData)

-- | Format a text messages that compares an 'Expected' with an 'Actual' value.
--
expectedMessage :: Show a => Expected a -> Actual a -> T.Text
expectedMessage (Expected e) (Actual a)
    = "Expected: " <> sshow e <> ", Actual: " <> sshow a

-- | Exceptions that are thrown by functions in "Data.MerkleLog". All functions
-- that throw exceptions can be called as pure functions in `Either
-- SomeException`.
--
data MerkleTreeException
    = EncodingSizeException T.Text (Expected Int) (Actual Int)
    | EncodingSizeConstraintException T.Text (Expected T.Text) (Actual Int)
    | IndexOutOfBoundsException T.Text (Expected (Int, Int)) (Actual Int)
    | InputNotInTreeException T.Text Int B.ByteString
    | MerkleRootNotInTreeException T.Text Int T.Text
    | InvalidProofObjectException T.Text
    | MalformedProofException T.Text
    | InvalidProofCompositionClaimType T.Text
    | InvalidProofCompositionClaimHash T.Text (Expected T.Text) (Actual T.Text)
    deriving (Eq, Generic)
    deriving anyclass (NFData)

instance Exception MerkleTreeException where
    displayException = T.unpack . textMessage

instance Show MerkleTreeException where
    show = T.unpack . textMessage

-- | Display 'MerkleTreeException' values as text messages.
--
textMessage :: MerkleTreeException -> T.Text
textMessage (EncodingSizeException ty e a)
    = "Failed to decode " <> ty <> " because the input is of wrong size"
    <> ". " <> expectedMessage e a
textMessage (EncodingSizeConstraintException ty (Expected e) (Actual a))
    = "Failed to decode " <> ty <> " because the input is of wrong size"
    <> ". " <> "Expected: " <> e
    <> ", " <> "Actual: " <> sshow a
textMessage (IndexOutOfBoundsException ty (Expected e) (Actual a))
    = "Index out of bounds"
    <> ". " <> ty
    <> ". " <> "Expected: " <> sshow e
    <> ", " <> "Actual: " <> sshow a
textMessage (InputNotInTreeException t i b)
    = "Item not in tree"
    <> ". " <> t
    <> ". Position: " <> sshow i
    <> ". Input (b64): " <> T.take 1024 (b64 b)
textMessage (MerkleRootNotInTreeException t i b)
    = "Item not in tree"
    <> ". " <> t
    <> ". Position: " <> sshow i
    <> ". root: " <> b
textMessage (InvalidProofObjectException t)
    = "Invalid ProofObject: " <> t
textMessage (MalformedProofException t)
    = "Malformed Proof. " <> t
textMessage (InvalidProofCompositionClaimType t)
    = t
    <> ". Invalid MerkleNodeType of right hand side claim in proof composition"
    <> ". Expected: TreeNode"
    <> ". Actual: InputNode"
textMessage (InvalidProofCompositionClaimHash t (Expected a) (Actual b))
    =  t
    <> ". The root of of the left hand side proof does not match the claim of the right hand side proof in proof composition"
    <> ". Expected: " <> a
    <> ". Actual: " <> b

inputNotInTreeException
    :: T.Text
    -> Int
    -> MerkleNodeType a
    -> MerkleTreeException
inputNotInTreeException t pos (TreeNode r)
    = MerkleRootNotInTreeException t pos (sshow r)
inputNotInTreeException t pos (InputNode b)
    = InputNotInTreeException t pos b

-- -------------------------------------------------------------------------- --
-- Hash Algorithm

-- | The class of types that has a representation as a 'ByteArray'.
--
class (ResetableHash a, Hash a) => MerkleHashAlgorithm a where
    digestBytes :: a -> ByteArray

    default digestBytes :: Coercible a ByteArray => a -> ByteArray
    digestBytes = coerce
    {-# INLINE digestBytes #-}

instance MerkleHashAlgorithm Sha2_224
instance MerkleHashAlgorithm Sha2_256
instance MerkleHashAlgorithm Sha2_384
instance MerkleHashAlgorithm Sha2_512_224
instance MerkleHashAlgorithm Sha2_512_256
instance MerkleHashAlgorithm Sha3_224
instance MerkleHashAlgorithm Sha3_256
instance MerkleHashAlgorithm Sha3_384
instance MerkleHashAlgorithm Sha3_512
instance MerkleHashAlgorithm Keccak224
instance MerkleHashAlgorithm Keccak256
instance MerkleHashAlgorithm Keccak384
instance MerkleHashAlgorithm Keccak512
instance MerkleHashAlgorithm Blake2s256
instance MerkleHashAlgorithm Blake2b512
instance KnownNat n => MerkleHashAlgorithm (Shake128 n)
instance KnownNat n => MerkleHashAlgorithm (Shake256 n)

-- | The size of 'MerkleHash' values in bytes.
--
hashSize :: forall a c . IncrementalHash a => Num c => c
hashSize = digestSize @a
{-# INLINE hashSize #-}

nullHash :: forall a . Hash a => a
nullHash = hashByteArray_ @a mempty
{-# INLINE nullHash #-}

nullHashBytes :: forall a . MerkleHashAlgorithm a => ByteArray
nullHashBytes = digestBytes $ nullHash @a
{-# INLINE nullHashBytes #-}

-- -------------------------------------------------------------------------- --
-- Merkle Root

-- TODO: when computing the root from the leafs it is not necessary to store the
-- full tree. Instead only the hashes of full trees need to be persisted on a
-- stack. Similarly, when computing proof, not all nodes need to be stored.

-- | The root of a Merkle tree.
--
-- The constructor of this type is considered internal.
--
newtype MerkleRoot a = MerkleRoot ByteArray
    deriving (Eq, Ord, Generic)
    deriving newtype (NFData)
    deriving (Show) via Base64Encoded

-- | Size of a MerkleRoot in Bytes
--
merkleRootSize :: forall a c . IncrementalHash a => Num c => c
merkleRootSize = digestSize @a
{-# INLINE merkleRootSize #-}

-- | Encode a Merkle tree root into binary format.
--
encodeMerkleRoot :: MerkleHashAlgorithm a => MerkleRoot a -> B.ByteString
encodeMerkleRoot (MerkleRoot r) = fromByteArray r
{-# INLINE encodeMerkleRoot #-}

merkleRootBytes:: MerkleRoot a -> ByteArray
merkleRootBytes (MerkleRoot r) = r
{-# INLINE merkleRootBytes #-}

-- | Decode a Merkle tree root from a binary representation.
--
decodeMerkleRoot
    :: forall a m
    . MonadThrow m
    => IncrementalHash a
    => B.ByteString
    -> m (MerkleRoot a)
decodeMerkleRoot b
    | B.length b /= digestSize @a = throwM e
    | otherwise = return $ MerkleRoot $ toByteArray b
  where
    e = EncodingSizeException "MerkleRoot"
        (Expected (digestSize @a @Int))
        (Actual (B.length b))
{-# INLINE decodeMerkleRoot #-}

finalizeRoot
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> IO (MerkleRoot a)
finalizeRoot ctx = MerkleRoot . digestBytes <$> finalize @a ctx
{-# INLINE finalizeRoot #-}

-- -------------------------------------------------------------------------- --
-- MerkleNode Type

-- | The Type of leaf nodes in a Merkle tree. A node is either an input value
-- or a root of another nested Merkle tree.
--
data MerkleNodeType a
    = TreeNode (MerkleRoot a)
    | InputNode B.ByteString
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (NFData)

-- -------------------------------------------------------------------------- --
-- Hash Computations

leafTag :: ByteArray
leafTag = [0]
{-# INLINE leafTag #-}

nodeTag :: ByteArray
nodeTag = [1]
{-# INLINE nodeTag #-}

-- | Compute hash for a leaf node in a Merkle tree.
--
merkleLeaf
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleNodeType a
    -> MerkleRoot a
merkleLeaf (TreeNode h) = h
merkleLeaf (InputNode b) = unsafeDupablePerformIO $ do
    !ctx <- initialize @a
    -- on small inputs it can be more efficient to concatenate the input and
    -- update the hash context only once. However, On large inputs that is very
    -- inefficient, because the complete bytestring must be copied.
    --
    updateByteArray @a ctx leafTag
    updateByteString @a ctx b
    finalizeRoot @a ctx
{-# INLINE merkleLeaf #-}

-- | Compute hash for an inner node of a Merkle tree.
--
merkleNode
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleRoot a
    -> MerkleRoot a
    -> MerkleRoot a
merkleNode !(MerkleRoot a) !(MerkleRoot b) = unsafeDupablePerformIO $ do
    !ctx <- initialize @a
    updateByteArray @a ctx $ nodeTag <> a <> b
    finalizeRoot @a ctx
{-# INLINE merkleNode #-}

merkleLeafIO
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> MerkleNodeType a
    -> IO (MerkleRoot a)
merkleLeafIO _ (TreeNode h) = return h
merkleLeafIO ctx (InputNode b) = do
    reset @a ctx
    -- on small inputs it can be more efficient to concatenate the input and
    -- update the hash context only once. However, On large inputs that is very
    -- inefficient, because the complete bytestring must be copied.
    --
    updateByteArray @a ctx leafTag
    updateByteString @a ctx b
    finalizeRoot @a ctx
{-# INLINE merkleLeafIO #-}

merkleNodeIO
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> MerkleRoot a
    -> MerkleRoot a
    -> IO (MerkleRoot a)
merkleNodeIO ctx !(MerkleRoot a) !(MerkleRoot b) = do
    reset @a ctx
    -- benchmarks indicate that it is beneficial to concatenate small (unpinned)
    -- bytearrays an make a single call to the hash function.
    updateByteArray @a ctx $ nodeTag <> a <> b
    finalizeRoot @a ctx
{-# INLINE merkleNodeIO #-}

