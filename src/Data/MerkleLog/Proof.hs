{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.Proof
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- This module provides methods to compute Merkle proofs directly from the
-- inputs without creating the full tree.
--
-- Proofs in this module are not compatible with proofs in "Data.MerkleLog". If
-- possible the format in this module should be preferred.
--
module Data.MerkleLog.Proof
( MerkleProof(..)
, merkleProof
, merkleProofIO
, merkleProofStream
, runProof
, runProofIO
, composeProofs
, composeProofsUnchecked
, concatProofs
, encodeProof
, decodeProof
) where

import Control.Exception (throwIO)
import Control.Monad
import Control.Monad.Catch
import Data.Array.Byte
import Data.Bits
import Data.ByteString qualified as B
import Data.ByteString.Builder qualified as BB
import Data.ByteString.Lazy qualified as BL
import Data.ByteString.Short qualified as BS
import Data.ByteString.Unsafe qualified as B
import Data.Coerce
import Data.Foldable1
import Data.Hash.Class.Mutable
import Data.List.NonEmpty qualified as NE
import Data.MerkleLog.Internal
import Data.MerkleLog.Utils
import Data.Word
import Foreign
import Numeric.Natural
import Streaming.Prelude qualified as S
import System.IO.Unsafe

-- -------------------------------------------------------------------------- --
-- Root of a Merkle tree

-- | This type represents the proof trace as a list of bits starting with the
-- least significant bit.
--
-- We use a natural number for representing the bits because it is of unbounded
-- size and the Haskell base library includes a 'Bit's instance for it. Any
-- number of leading zeros is implicitely assumed. The overall number bits that
-- are used in the proof is determined by the number of hashes.
--
newtype ProofTrace = ProofTrace Natural
    deriving (Show, Eq, Ord)
    deriving newtype (Num, Bits, Real, Enum, Integral)

-- | Merkle Proof
--
-- In this data structure the proof claim is usually much larger than the
-- evidence. Therefore there is no point in optimizing the handling of the proof
-- evidence data.
--
-- In practice the evidence part of a proof is small. Even proofs from
-- degenerated, unbalanced trees, which can arise from the composition of
-- proofs, should not be larger than a few dozen steps.
--
data MerkleProof a = MerkleProof
    { _merkleProofClaim :: !(MerkleNodeType a)
    , _merkleProofTrace :: !ProofTrace
    , _merkleProofEvidence :: ![MerkleRoot a]
    }
    deriving (Show, Eq)

-- | Compose two proofs where the root of the first proof matches the claim of
-- the second proof.
--
-- Verifying proofs is cheap and this function checks that the proofs are
-- actually composable
--
-- NOTE: be careful when calling this function repeatedly. When you compose
-- several proofs you should do it backward starting with the laste proof in
-- order to avoid quadratic time complexity due to repeated verification of the
-- right hand side proof prefixes.
--
composeProofs
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => MerkleProof a
    -> MerkleProof a
    -> m (MerkleProof a)
composeProofs _ MerkleProof { _merkleProofClaim = InputNode _ } =
    throwM $ InvalidProofCompositionClaimType "composeProof"
composeProofs a b@(MerkleProof { _merkleProofClaim = TreeNode n }) = do
    unless (r == n) $
        throwM $ InvalidProofCompositionClaimHash "composeProof"
            (Expected (sshow n))
            (Actual (sshow r))
    return $ MerkleProof
        { _merkleProofClaim = _merkleProofClaim a
        , _merkleProofTrace = trace
        , _merkleProofEvidence = evidence
        }
  where
    r = runProof a
    al = length (_merkleProofEvidence a)
    trace = _merkleProofTrace a .|. shiftL (_merkleProofTrace b) al
    evidence = _merkleProofEvidence a <> _merkleProofEvidence b

-- | This folds from right to left and runs in O(n) time.
--
-- Folding from left to right would result in quadratic time complexity, due to
-- repeated verification of right hand side proof prefixes.
--
concatProofs
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => NE.NonEmpty (MerkleProof a)
    -> m (MerkleProof a)
concatProofs = foldrM1 (composeProofs @a)

-- | Compose proofs without checking that the proofs are composable. This avoids
-- the overhead of verifying the proofs. In particular, it can be used to
-- efficiently compose several proofs from left to right.
--
composeProofsUnchecked
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => MerkleProof a
    -> MerkleProof a
    -> m (MerkleProof a)
composeProofsUnchecked _ MerkleProof { _merkleProofClaim = InputNode _ } =
    throwM $ InvalidProofCompositionClaimType "composeProof"
composeProofsUnchecked a b  = do
    return $ MerkleProof
        { _merkleProofClaim = _merkleProofClaim a
        , _merkleProofTrace = trace
        , _merkleProofEvidence = evidence
        }
  where
    al = length (_merkleProofEvidence a)
    trace = _merkleProofTrace a .|. shiftL (_merkleProofTrace b) al
    evidence = _merkleProofEvidence a <> _merkleProofEvidence b

-- -------------------------------------------------------------------------- --
-- Proof computation

-- | Compute the root of a Merkle tree
--
merkleProof
    :: forall a m
    . MonadThrow m
    => MerkleHashAlgorithm a
    => Int
    -> [MerkleNodeType a]
    -> m (MerkleProof a)
merkleProof pos l =
    case unsafePerformIO $ try (merkleProofIO @a pos l) of
        Left e -> throwM @_ @MerkleTreeException e
        Right p -> return p

merkleProofIO
    :: forall a
    . MerkleHashAlgorithm a
    => Int
    -> [MerkleNodeType a]
    -> IO (MerkleProof a)
merkleProofIO pos l = do
    ctx <- initialize @a
    (idx, s, t, p, c) <- foldM (step ctx pos) initialProofState l
    finalReduce ctx c pos (idx - 1) t p s

merkleProofStream
    :: forall a
    . MerkleHashAlgorithm a
    => Int
    -> S.Stream (S.Of (MerkleNodeType a)) IO ()
    -> IO (MerkleProof a)
merkleProofStream pos l = do
    ctx <- initialize @a
    S.foldM_
        (step ctx pos)
        (return initialProofState)
        (\(idx, s, t, p, c) -> finalReduce ctx c pos (idx - 1) t p s)
        l

-- -------------------------------------------------------------------------- --
-- Implementation
--
-- The implementation reads a stream of leafs and simulates a parallel tree
-- contraction by storing intermediate results on a stack.

-- TODO: check how a proper monad transformer performs, which would ideally
-- compile down to the same binary code but would be more readable.

type ProofState a =
    ( Int
        -- The current position in the input stream
    , [MerkleRoot a]
        -- ^ the current stack
    , Word
        -- ^ the proof trace
    , [MerkleRoot a]
        -- ^ the proof hashes
    , Maybe (MerkleNodeType a)
        -- ^ the proof claim
    )

initialProofState :: ProofState a
initialProofState = (0, [], 0, [], Nothing)
{-# INLINE initialProofState #-}

step
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> Int
    -> ProofState a
    -> MerkleNodeType a
    -> IO (ProofState a)
step ctx pos (i, s, t, p, c) h = do
    !n <- merkleLeafIO ctx h
    (!t', !p', !s') <- reduce ctx pos i t p (n:s)
    return (i+1, s', t', p', c')
  where
    !c' = if i == pos then Just h else c
{-# INLINE step #-}

reduce
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> Int
        -- claim position prefix
    -> Int
        -- idx prefix
    -> Word
        -- trace
    -> [MerkleRoot a]
        -- proof
    -> [MerkleRoot a]
        -- stack
    -> IO (Word, [MerkleRoot a], [MerkleRoot a])
reduce _ _ idx t p s | not (testBit idx 0) = return (t, p, s)
reduce ctx pos idx t p (r0 : r1 : r) = do
    !n <- merkleNodeIO ctx r1 r0
    reduce ctx pos' idx' t' p' $ n : r
  where
    (!t', !p') = if pos' == idx'
        then if testBit pos 0
            then (setBit t (length p), r1:p)
            else (t, r0:p)
        else (t, p)
    !pos' = shiftR pos 1
    !idx' = shiftR idx 1
reduce _ _ _ _ _ s = error $ "Data.MerkleLog.Proof.V2.reduce: Can not happen: stack length " <> show (length s)
{-# INLINE reduce #-}

-- | Final reduction step loop. This is needed for trees that are not full
-- trees, i.e. trees where the number of leafs is not a power of two.
--
-- If we only wanted to compute the root, we could just reduce the stack
-- until only a final hash is left. The logic becomes more complex due to the
-- proof evidence and proof trace computation.
--
finalReduce
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> Maybe (MerkleNodeType a)
    -> Int
    -> Int
    -> Word
    -> [MerkleRoot a]
    -> [MerkleRoot a]
    -> IO (MerkleProof a)
finalReduce _ Nothing pos idx _ _ _ = throwIO $ IndexOutOfBoundsException
    "merkleProof.finalReduce (claim not found)"
    (Expected (0, idx-1))
    (Actual pos)
finalReduce ctx (Just c) pos idx t_ p_ l_ = do
    -- we need to know where we in the stack. The tress for trailing ones at the
    -- current index have have already been filled when reduce was called on the
    -- last item. Hence, we skip those ones before we proceed with the final
    -- stack reduction.
    go (shiftR pos skip0) (shiftR idx skip0) t_ p_ l_
  where
    skip0 = countTrailingZeros (complement idx)

    go _pos _idx t p [_] = do
        return MerkleProof
            { _merkleProofClaim = c
            , _merkleProofTrace = int t
            , _merkleProofEvidence = reverse p
            }
    go pos0 idx0 t p (r0 : r1 : r) = do
        !n <- merkleNodeIO ctx r1 r0
        go pos' idx' t' p' $ n : r
      where
        (!t', !p') = if pos' == idx'
            then if testBit pos1 0
                then (setBit t (length p), r1:p)
                else (t, r0:p)
            else (t, p)

        -- skip over trailing zeros, because this is the last idx and there's
        -- nothing on the right side of it:
        skip1 = countTrailingZeros idx0
        idx1 = shiftR idx0 skip1
        pos1 = shiftR pos0 skip1

        -- new values for the next round
        !pos' = shiftR pos1 1
        !idx' = shiftR idx1 1
    go _ _ _ _ [] =
        throwM $  IndexOutOfBoundsException
            "merkleProof.finalReduce (invalid proof)"
            (Expected (0, idx-1))
            (Actual pos)
{-# INLINE finalReduce #-}

-- -------------------------------------------------------------------------- --
-- Verify Proof

runProof
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleProof a
    -> MerkleRoot a
runProof = unsafeDupablePerformIO . runProofIO
{-# INLINE runProof #-}

runProofIO
    :: forall a
    . MerkleHashAlgorithm a
    => MerkleProof a
    -> IO (MerkleRoot a)
runProofIO proof = do
    ctx <- initialize @a
    h0 <- merkleLeafIO ctx $ _merkleProofClaim proof
    go ctx (_merkleProofTrace proof) h0 (_merkleProofEvidence proof)
  where
    go _ _ r [] = return r
    go ctx t h0 (h1:r) = do
        !n <- if testBit t 0
            then merkleNodeIO ctx h1 h0
            else merkleNodeIO ctx h0 h1
        go ctx (shiftR t 1) n r

-- -------------------------------------------------------------------------- --
-- Proof Serialization

-- | Binary Encoding of Proofs
--
-- The serialization does not include the hash algorithm.
--
-- Note, that this is a rather naive portable encoding. For production scenarios
-- it is recommened to use more efficient application specific encodings where
-- possible.
--
encodeProof :: MerkleProof a -> B.ByteString
encodeProof = BL.toStrict . BB.toLazyByteString . encodeProof'
{-# INLINE encodeProof #-}

-- | Serialize a proof to a bytestring builder.
--
encodeProof' :: MerkleProof a -> BB.Builder
encodeProof' proof
    = BB.word64LE (int el)
    <> encodeTrace el trace
    <> foldMap putBytes (_merkleProofEvidence proof)
    <> case _merkleProofClaim proof of
        InputNode b -> putBytes leafTag <> BB.byteString b
        TreeNode r -> putBytes nodeTag <> putBytes r
  where
    el = length $ _merkleProofEvidence proof
    trace = int $ _merkleProofTrace proof

-- | We encode a natural number with the least number of bytes that are
-- sufficient to represent it in an unsigned little endian encoding.
--
-- The result is padded with 0x0 bytes to the smallest number of bytes that can
-- encode the length of the trace
--
encodeTrace :: Int -> Natural -> BB.Builder
encodeTrace s t = case t of
    0 -> BB.word8 0 <> go (max 0 (s-8)) 0
    _ -> go s t
  where
    go :: Int -> Natural -> BB.Builder
    go 0 0 = mempty
    go l 0 = BB.word8 0x0 <> go (max 0 (l-8)) 0
    go l i = BB.word8 (int m) <> go (max 0 (l-8)) n
      where
        (n,m) = quotRem i 256

putBytes :: Coercible a ByteArray => a -> BB.Builder
putBytes = BB.shortByteString . coerce
{-# INLINE putBytes #-}

-- | Decode a proof that was serialized with 'encodeProof'
--
decodeProof
    :: forall a m
    . MonadThrow m
    => IncrementalHash a
    => B.ByteString
    -> m (MerkleProof a)
decodeProof b = do
    when (B.length b < 9) $
        throwM $ EncodingSizeConstraintException
            "Proof"
            (Expected "at least 16 bytes")
            (Actual $ B.length b)
    el <- getEl
    tr <- getTr el
    when (B.length b < 8 + traceLength el + hs * el) $
        throwM $ EncodingSizeConstraintException
            "Proof"
            (Expected $ "at least " <> sshow (8 + traceLength el) <> " bytes plus the hash size times the number of steps")
            (Actual $ B.length b)
    ev <- getEv el
    when (B.length b < 8 + traceLength el + hs * el + 1) $
        throwM $ EncodingSizeConstraintException
            "Proof"
            (Expected $ "The proof must include at least 1 byte for the tag of the claim type, in total it must have at least " <> sshow (16 + hs * el + 1) <> " bytes")
            (Actual $ B.length b)
    cl <- getTag el >>= \case
        0 -> getInputNode el
        1 -> getTreeNode el
        e -> throwM $ MalformedProofException $ "unknown node tag: " <> sshow e
    return $ MerkleProof
        { _merkleProofClaim = cl
        , _merkleProofTrace = tr
        , _merkleProofEvidence = ev
        }
  where
    getEl = return $
        unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, _) ->
            int @Word64 @Int . le64 <$> peek @Word64 (plusPtr ptr 0)

    getTr el = return $ ProofTrace $
        unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, _) -> foldM
            (\(!c) i -> do
                n <- int @Word8 @Natural <$> peek @Word8 (plusPtr ptr (8 + i))
                return (c + shiftL n (i * 8))
            )
            0
            [0 .. traceLength el - 1]

    getEv el = return $
        unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, _) ->
            forM [0 .. el-1] $ \i -> MerkleRoot . coerce
                <$> BS.packCStringLen (plusPtr ptr (8 + traceLength el + hs * i), hs)

    getTag el = return $
        unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, _) ->
            peek @Word8 (plusPtr ptr (8 + traceLength el + hs * el))

    getInputNode el = return $ InputNode <$>
        unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, l) ->
            B.packCStringLen (plusPtr ptr offset, l - offset)
      where
        offset = 8 + traceLength el + 1 + hs * el

    getTreeNode el = return $ TreeNode . coerce <$>
        unsafeDupablePerformIO $ B.unsafeUseAsCStringLen b $ \(ptr, l) ->
            BS.packCStringLen (plusPtr ptr offset, l - offset)
      where
        offset = 8 + traceLength el + 1 + hs * el

    hs = hashSize @a
    traceLength el = 1 + quot (el - 1) 8
