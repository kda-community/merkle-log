{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Data.MerkleLog.NullHash
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.NullHash
( NullHash(..)
) where

import Data.Array.Byte
import Data.ByteString.Short qualified as BS
import Data.Hash.Class.Mutable
import Data.Hash.Internal.Utils
import Data.MerkleLog.Common
import Data.MerkleLog.Utils
import Data.MerkleLog.V1.Primitive
import Data.String
import GHC.Exts
import GHC.TypeNats

newtype NullHash (n :: Natural) = NullHash ByteArray
    deriving (Eq, Ord)
    deriving (Show, IsString) via B16ShortByteString

instance KnownNat n => MerkleHashAlgorithm (NullHash n)

instance KnownNat n => Hash (NullHash n) where
    initialize = return ()
    {-# INLINE initialize #-}

instance KnownNat n => IncrementalHash (NullHash n) where
    type Context (NullHash n) = ()
    type DigestSize (NullHash n) = n
    update# () _ _ _ = return ()
    finalize () = return $ nullHash @n
    finalize# () arr off =
        copyByteArray (nullHashBytes @n) 0
            (MutableByteArray arr)
            (I# off)
            (natVal_ @n)
    {-# INLINE update# #-}
    {-# INLINE finalize# #-}

instance KnownNat n => ResetableHash (NullHash n) where
    reset () = return ()
    {-# INLINE reset #-}

nullHash :: forall n . KnownNat n => NullHash n
nullHash = NullHash (nullHashBytes @n)

nullHashBytes :: forall n . KnownNat n => ByteArray
nullHashBytes = coerce $ BS.replicate (int $ natVal' @n proxy#) 0x00

