{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Data.MerkleLog.V1.Primitive
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- Primitive operations for dealing more comfortably with ByteArray's.
--
-- The API for ShortByteString is very restrictive and lacks some important
-- features. The primtive package provides many of those features for
-- ByteArray's in base but comes with additional dependencies.
--
-- This modules offers a subset of the functionality of the primtives package,
-- avoiding unnecessary all features, dependencies, and backward compability.
--
module Data.MerkleLog.V1.Primitive
( PrimMonad(..)

-- * ByteArray
, newByteArray
, byteArraySize
, mutableByteArraySize
, sameByteArray
, sameMutableByteArray
, compareByteArrays
, unsafeFreezeByteArray
, shrinkMutableByteArray
, resizeMutableByteArray
, growByteArray
, growByteArrayFor
, createByteArray
, createByteArrayM
, copyByteArray
, copyMutableByteArray

-- ** Writing
, write8
, write32Be
, write64Be

-- ** Reading
, indexWord8Array
, indexWord16Array
, indexWord32Array
, indexWord64Array
, indexWord16ArrayBe
, indexWord32ArrayBe
, indexWord64ArrayBe

-- * Lowlevel
, keepAliveUnlifted

) where

import Control.Monad.Catch
import Data.Array.Byte
import Data.Bits
import Data.Kind
import Data.MerkleLog.Utils
import GHC.Exts
import GHC.IO
import GHC.ST
import GHC.Word

-- -------------------------------------------------------------------------- --
-- Primitive Monads

class Monad m => PrimMonad m where
    type PrimState m
    primitive :: (State# (PrimState m) -> (# State# (PrimState m), a #)) -> m a
    internal :: m a -> State# (PrimState m) -> (# State# (PrimState m), a #)

instance PrimMonad IO where
    type PrimState IO = RealWorld
    primitive = IO
    internal (IO p) = p
    {-# INLINE primitive #-}

instance PrimMonad (ST s) where
    type PrimState (ST s) = s
    primitive = ST
    internal (ST p) = p
    {-# INLINE primitive #-}

class (PrimMonad m, s ~ PrimState m) => MonadPrim s m
instance (PrimMonad m, s ~ PrimState m) => MonadPrim s m

-- -------------------------------------------------------------------------- --
-- ByteArray

-- Our main focus is on (unaligned) Word32 operations on ByteArrays
--
-- (if unaligned operations turns out to be inefficient or otherwise difficult
-- we should consider changing the proof format by storing trace first and the
-- hashes only after that)

sameByteArray :: ByteArray -> ByteArray -> Bool
sameByteArray !(ByteArray a#) !(ByteArray b#) =
    isTrue# (sameByteArray# a# b#)

compareByteArrays :: ByteArray -> Int -> ByteArray -> Int -> Int -> Ordering
compareByteArrays !(ByteArray a#) !(I# ao#) !(ByteArray b#) (I# bo#) !(I# l#) =
    compare (I# (compareByteArrays# a# ao# b# bo# l#)) 0

sameMutableByteArray :: MutableByteArray s -> MutableByteArray s -> Bool
sameMutableByteArray !(MutableByteArray a#) !(MutableByteArray b#) =
    isTrue# (sameMutableByteArray# a# b#)

newByteArray
    :: PrimMonad m
    => Int
    -> m (MutableByteArray (PrimState m))
newByteArray (I# i#) = primitive $ \s -> case newByteArray# i# s of
    (# s', marr# #) -> (# s', MutableByteArray marr# #)
{-# INLINE newByteArray #-}

byteArraySize :: ByteArray -> Int
byteArraySize (ByteArray arr#) = I# (sizeofByteArray# arr#)
{-# INLINE byteArraySize #-}

mutableByteArraySize
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> m Int
mutableByteArraySize (MutableByteArray marr#) = primitive $ \s ->
    case getSizeofMutableByteArray# marr# s of
        (# s', n #) -> (# s', I# n #)
{-# INLINE mutableByteArraySize #-}

unsafeFreezeByteArray
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> m ByteArray
unsafeFreezeByteArray !(MutableByteArray marr#) = primitive $ \s ->
    case unsafeFreezeByteArray# marr# s of
        (# s', arr# #) -> (# s', ByteArray arr# #)
{-# INLINE unsafeFreezeByteArray #-}

shrinkMutableByteArray
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> Int
    -> m ()
shrinkMutableByteArray !(MutableByteArray marr#) !(I# i#) = primitive $ \s ->
    case shrinkMutableByteArray# marr# i# s of
        s' -> (# s', () #)
{-# INLINE shrinkMutableByteArray #-}

resizeMutableByteArray
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> Int
    -> m (MutableByteArray (PrimState m))
resizeMutableByteArray !(MutableByteArray marr#) !(I# i#) = primitive $ \s ->
    case resizeMutableByteArray# marr# i# s of
        (# s', marr'# #) -> (# s', MutableByteArray marr'# #)
{-# INLINE resizeMutableByteArray #-}

growByteArray
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> m (MutableByteArray (PrimState m))
growByteArray marr = do
    cur <- mutableByteArraySize marr
    resizeMutableByteArray marr (cur * 2)
{-# INLINABLE growByteArray #-}

growByteArrayFor
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> Int
    -> m (MutableByteArray (PrimState m))
growByteArrayFor marr requested = do
    cur <- mutableByteArraySize marr
    if (cur < requested)
      then do
        let x = bit (finiteBitSize @Int undefined - countLeadingZeros requested)
        resizeMutableByteArray marr x
      else
        return marr
{-# INLINABLE growByteArrayFor #-}

createByteArray
    :: Int
    -> (MutableByteArray RealWorld -> IO ())
    -> ByteArray
createByteArray !(I# n#) f = ByteArray $ runRW# $ \s0 ->
    case newByteArray# n# s0 of
        (# s1, a #) -> case unIO (f (MutableByteArray a)) s1 of
            (# s2, () #) -> case unsafeFreezeByteArray# a s2 of
                (# _, arr #) -> arr
{-# INLINE createByteArray #-}

createByteArrayM
    :: MonadThrow m
    => Int
    -> (MutableByteArray RealWorld -> IO ())
    -> m ByteArray
createByteArrayM !(I# n#) f = case go of
    Left e -> throwM e
    Right a -> return a
  where
    go = runRW# $ \s0 -> case newByteArray# n# s0 of
        (# s1, a #) -> case unIO (tryAllSync (f (MutableByteArray a))) s1 of
            (# _, Left e #) -> Left e
            (# s2, Right () #) -> case unsafeFreezeByteArray# a s2 of
                (# _, arr #) -> Right (ByteArray arr)
{-# INLINE createByteArrayM #-}

copyByteArray
    :: PrimMonad m
    => ByteArray
    -> Int
    -> MutableByteArray (PrimState m)
    -> Int
    -> Int
    -> m ()
copyByteArray !(ByteArray src#) !(I# so#) !(MutableByteArray trg#) !(I# to#) !(I# len#) =
    primitive $ \s ->
        case copyByteArray# src# so# trg# to# len# s of
            s' -> (# s', () #)
{-# INLINE copyByteArray #-}

copyMutableByteArray
    :: PrimMonad m
    => MutableByteArray (PrimState m)
    -> Int
    -> MutableByteArray (PrimState m)
    -> Int
    -> Int
    -> m ()
copyMutableByteArray !(MutableByteArray src#) !(I# so#) !(MutableByteArray trg#) !(I# to#) !(I# len#) =
    primitive $ \s ->
        case copyMutableByteArray# src# so# trg# to# len# s of
            s' -> (# s', () #)
{-# INLINE copyMutableByteArray #-}

write8
    :: PrimMonad m
    => Integral a
    => MutableByteArray (PrimState m)
    -> Int
    -> a
    -> m ()
write8 !(MutableByteArray marr#) !(I# off#) v = primitive $ \s ->
    case writeWord8Array# marr# off# v# s of
        s' -> (# s', () #)
  where
    !(W8# v#) = int v
{-# INLINE write8 #-}

write32Be
    :: PrimMonad m
    => Integral a
    => MutableByteArray (PrimState m)
    -> Int
    -> a
    -> m ()
write32Be !(MutableByteArray marr#) !(I# off#) v = primitive $ \s ->
    case writeWord32Array# marr# off# v# s of
        s' -> (# s', () #)
  where
    !(W32# v#) = be32 (int v)
{-# INLINE write32Be #-}

write64Be
    :: PrimMonad m
    => Integral a
    => MutableByteArray (PrimState m)
    -> Int
    -> a
    -> m ()
write64Be !(MutableByteArray marr#) !(I# off#) v = primitive $ \s ->
    case writeWord64Array# marr# off# v# s of
        s' -> (# s', () #)
  where
    !(W64# v#) = be64 (int v)
{-# INLINE write64Be #-}

indexWord8Array
    :: ByteArray
    -> Int
    -> Word8
indexWord8Array !(ByteArray arr#) !(I# off#) =
    W8# (indexWord8Array# arr# off#)
{-# INLINE indexWord8Array #-}

indexWord16Array
    :: ByteArray
    -> Int
    -> Word16
indexWord16Array !(ByteArray arr#) !(I# off#) =
    W16# (indexWord16Array# arr# off#)
{-# INLINE indexWord16Array #-}

indexWord32Array
    :: ByteArray
    -> Int
    -> Word32
indexWord32Array !(ByteArray arr#) !(I# off#) =
    W32# (indexWord32Array# arr# off#)
{-# INLINE indexWord32Array #-}

indexWord64Array
    :: ByteArray
    -> Int
    -> Word64
indexWord64Array !(ByteArray arr#) !(I# off#) =
    W64# (indexWord64Array# arr# off#)
{-# INLINE indexWord64Array #-}

indexWord16ArrayBe
    :: ByteArray
    -> Int
    -> Word16
indexWord16ArrayBe !(ByteArray arr#) !(I# off#) =
    be16 $ W16# (indexWord16Array# arr# off#)
{-# INLINE indexWord16ArrayBe #-}

indexWord32ArrayBe
    :: ByteArray
    -> Int
    -> Word32
indexWord32ArrayBe !(ByteArray arr#) !(I# off#) =
    be32 $ W32# (indexWord32Array# arr# off#)
{-# INLINE indexWord32ArrayBe #-}

indexWord64ArrayBe
    :: ByteArray
    -> Int
    -> Word64
indexWord64ArrayBe !(ByteArray arr#) !(I# off#) =
    be64 $ W64# (indexWord64Array# arr# off#)
{-# INLINE indexWord64ArrayBe #-}

-- -------------------------------------------------------------------------- --
-- Do we need any of the following?

-- | Variant of 'keepAlive' in which the value kept alive is of an unlifted
-- boxed type.
--
keepAliveUnlifted
    :: forall (m :: Type -> Type) (a :: UnliftedType) (r :: Type)
    . PrimMonad m
    => a
    -> m r
    -> m r
{-# INLINE keepAliveUnlifted #-}
keepAliveUnlifted x k =
    primitive $ \s0 -> keepAliveUnliftedLifted# x s0 (internal k)

keepAliveUnliftedLifted# :: forall (s :: Type) (a :: UnliftedType) (b :: Type).
     a
  -> State# s
  -> (State# s -> (# State# s, b #))
  -> (# State# s, b #)
{-# inline keepAliveUnliftedLifted# #-}
keepAliveUnliftedLifted# x s0 f =
  (unsafeCoerce# :: (# State# RealWorld, b #) -> (# State# s, b #))
    ( keepAlive# x
      ((unsafeCoerce# :: State# s -> State# RealWorld) s0)
      ((unsafeCoerce# ::
         (State# s -> (# State# s, b #)) ->
         (State# RealWorld -> (# State# RealWorld, b #))
       ) f)
    )
