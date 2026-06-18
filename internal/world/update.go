package world

import (
	"wowsandbox/internal/character"
	"wowsandbox/internal/packet"
)

// Vanilla (build 5875) update-field indices (mangos-zero UpdateFields.h).
const (
	objectFieldGUID          = 0
	objectFieldType          = 2
	objectFieldScaleX        = 4
	unitFieldHealth          = 22
	unitFieldMaxHealth       = 28
	unitFieldLevel           = 34
	unitFieldFactionTemplate = 35
	unitFieldBytes0          = 36
	unitFieldDisplayID       = 131
	unitFieldNativeDisplayID = 132
	playerBytes              = 193
	playerBytes2             = 194
	playerBytes3             = 195
)

const (
	updateTypeCreate2    = 3          // CREATE_OBJECT2
	typeIDPlayer         = 4          // ObjectType in the update block
	objectTypePlayer     = 25         // OBJECT_FIELD_TYPE value: OBJECT|UNIT|PLAYER
	updateFlagSelfLiving = 0x31       // SELF|ALL|LIVING
	floatOne             = 0x3F800000 // 1.0f bit pattern
)

// packedGUID encodes a u64 as a mask byte (bit i set if byte i is non-zero)
// followed by the non-zero bytes, least-significant first.
func packedGUID(guid uint64) []byte {
	var mask byte
	var data []byte
	for i := 0; i < 8; i++ {
		b := byte(guid >> (uint(i) * 8))
		if b != 0 {
			mask |= 1 << uint(i)
			data = append(data, b)
		}
	}
	return append([]byte{mask}, data...)
}

type fieldValue struct {
	index int
	value uint32
}

// buildUpdateMask writes block_count, the mask blocks, then the values.
// fields must be sorted ascending by index.
func buildUpdateMask(w *packet.Writer, fields []fieldValue) {
	maxIndex := fields[len(fields)-1].index
	blocks := maxIndex/32 + 1
	mask := make([]uint32, blocks)
	for _, f := range fields {
		mask[f.index/32] |= 1 << uint(f.index%32)
	}
	w.U8(uint8(blocks))
	for _, m := range mask {
		w.U32(m)
	}
	for _, f := range fields {
		w.U32(f.value)
	}
}

func humanDisplayID(gender uint8) uint32 {
	if gender == 0 {
		return 49 // human male
	}
	return 50 // human female
}

// buildCreatePlayer builds an SMSG_UPDATE_OBJECT body creating the player's
// own character object (CREATE_OBJECT2 + SELF|ALL|LIVING).
func buildCreatePlayer(ch *character.Character) []byte {
	w := packet.NewWriter()
	w.U32(1) // amount_of_objects
	w.U8(0)  // has_transport
	w.U8(updateTypeCreate2)
	w.Raw(packedGUID(ch.GUID))
	w.U8(typeIDPlayer)

	// MovementBlock — update_flag SELF|ALL|LIVING.
	w.U8(updateFlagSelfLiving)
	w.U32(0) // movement flags (standing)
	w.U32(0) // timestamp
	w.F32(ch.X)
	w.F32(ch.Y)
	w.F32(ch.Z)
	w.F32(0)        // orientation
	w.F32(0)        // fall time
	w.F32(2.5)      // walk speed
	w.F32(7.0)      // run speed
	w.F32(4.5)      // run-back speed
	w.F32(4.722222) // swim speed
	w.F32(2.5)      // swim-back speed
	w.F32(3.141594) // turn rate
	w.U32(1)        // ALL: unknown1

	display := humanDisplayID(ch.Gender)
	bytes0 := uint32(ch.Race) | uint32(ch.Class)<<8 | uint32(ch.Gender)<<16 // power 0 (mana)
	pBytes := uint32(ch.Skin) | uint32(ch.Face)<<8 | uint32(ch.HairStyle)<<16 | uint32(ch.HairColor)<<24

	buildUpdateMask(w, []fieldValue{
		{objectFieldGUID, uint32(ch.GUID)},
		{objectFieldGUID + 1, uint32(ch.GUID >> 32)},
		{objectFieldType, objectTypePlayer},
		{objectFieldScaleX, floatOne},
		{unitFieldHealth, 100},
		{unitFieldMaxHealth, 100},
		{unitFieldLevel, uint32(ch.Level)},
		{unitFieldFactionTemplate, 1}, // human
		{unitFieldBytes0, bytes0},
		{unitFieldDisplayID, display},
		{unitFieldNativeDisplayID, display},
		{playerBytes, pBytes},
		{playerBytes2, uint32(ch.FacialHair)},
		{playerBytes3, uint32(ch.Gender)},
	})
	return w.Bytes()
}
