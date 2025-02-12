{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.V1.Slice
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.V1.Slice
( Slice(..)
, SliceN(..)
, sliceN
, unsafeSliceN
, getSliceN
, MutableSliceN(..)
, mutableSliceN
, copySliceN

-- * Hashes
, HashSlice
, MutableHashSlice
, updateHashSlice
, finalizeHashSlice
) where

import Data.Array.Byte
import Data.Hash.Class.Mutable
import Data.MerkleLog.Utils
import Data.MerkleLog.V1.Primitive
import GHC.Exts
import GHC.Stack
import GHC.TypeNats

-- -------------------------------------------------------------------------- --
-- Utils

natVal_# :: forall n . KnownNat n => Int#
natVal_# = let !(I# n) = natVal_ @n in n
{-# INLINE natVal_# #-}

-- --------------------------------------------------------------------------
-- Array Slices

data Slice = Slice
    {-# UNPACK #-} !Int#
    {-# UNPACK #-} !Int#
    {-# UNPACK #-} !ByteArray#

slice :: ByteArray -> Slice
slice (ByteArray arr) = Slice 0# (sizeofByteArray# arr) arr
{-# INLINE slice #-}

-- -------------------------------------------------------------------------- --
-- Statically Sized Slices

-- | Slices of static size
--
data SliceN (n :: Natural) = SliceN
    {-# UNPACK #-} !Int#
    {-# UNPACK #-} !ByteArray#

eqSlice :: KnownNat n => SliceN n -> SliceN n -> Bool
eqSlice !(SliceN @n o1# a1#) !(SliceN o2# a2#)
    | isTrue# (sameByteArray# a1# a2#) = True
    | otherwise = isTrue# $ compareByteArrays# a1# o1# a2# o2# (natVal_# @n) ==# 0#
{-# INLINE eqSlice #-}

instance KnownNat n => Eq (SliceN n) where
    (==) = eqSlice

sliceN :: Int -> ByteArray -> SliceN n
sliceN !(I# off#) !(ByteArray arr#) = SliceN off# arr#

unsafeSliceN :: forall n . HasCallStack => KnownNat n => ByteArray -> SliceN n
unsafeSliceN b
    | isTrue# (s# /=# natVal_# @n) = error "Data.MerkleLog.unsafeSliceN: wrong length"
    | otherwise = SliceN 0# arr#
  where
    !(Slice _ s# arr#) = slice b
{-# INLINE unsafeSliceN #-}

getSliceN :: KnownNat n => SliceN n -> ByteArray
getSliceN !(SliceN @n off# src#) = createByteArray (natVal_ @n) $ \marr -> do
    copyByteArray (ByteArray src#) (I# off#) marr 0 (natVal_ @n)

-- -------------------------------------------------------------------------- --
-- Mutable Statically Sized Slices

-- | This represents a view onto a mutable byte array.
--
-- Only the content of the byte array is mutable. The byte array itself as well
-- as the offset are immutable.
--
-- Any acces (in particular pattern matching on the constructor), must ensure
-- proper state threading. If the underlying array is mutated, moved, or GCed,
-- the slice become invalid.
--
data MutableSliceN s (n :: Natural) = MutableSliceN
    {-# UNPACK #-} !Int#
    {-# UNPACK #-} !(MutableByteArray# s)

-- | Note that the content of the bytearray is mutable. The MutableSlice itself
-- does not capture the state.
--
mutableSliceN :: Int -> MutableByteArray s -> MutableSliceN s n
mutableSliceN !(I# off) !(MutableByteArray arr#) = MutableSliceN off arr#

copySliceN
    :: PrimMonad m
    => KnownNat n
    => SliceN n
    -> MutableSliceN (PrimState m) n
    -> m ()
copySliceN !(SliceN @n soff# src#) !(MutableSliceN toff# trg#) =
    copyByteArray (ByteArray src#) (I# soff#) (MutableByteArray trg#) (I# toff#) n
  where
    n = natVal_ @n
{-# INLINE copySliceN #-}

-- -------------------------------------------------------------------------- --
-- Hashes

type HashSlice a = SliceN (DigestSize a)
type MutableHashSlice a = MutableSliceN RealWorld (DigestSize a)

updateHashSlice
    :: forall a
    . IncrementalHash a
    => Context a
    -> HashSlice a
    -> IO ()
updateHashSlice ctx (SliceN off a) = update# @a ctx a off (hashSize# @a)
{-# INLINE updateHashSlice #-}

finalizeHashSlice
    :: forall a
    . IncrementalHash a
    => Context a
    -> MutableHashSlice a
    -> IO ()
finalizeHashSlice ctx (MutableSliceN off a) = finalize# @a ctx a off
{-# INLINE finalizeHashSlice #-}

hashSize#
    :: forall a
    . IncrementalHash a
    => Int#
hashSize# = unI# (digestSize @a)
{-# INLINE hashSize# #-}

