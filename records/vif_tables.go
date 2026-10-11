package records

import "fmt"

// The value information tables of EN 13757-3:2025 clause 6.4, in our own
// words: quantity names are snake_case, units UCUM / SenML symbols.

// vifKind says how the data field is read.
type vifKind int

const (
	vkNumber    vifKind = iota // type B (signed) or BCD or real, scaled
	vkUnsigned                 // type C (unsigned) or BCD (Annex A)
	vkBits                     // type D: bit array, reported as hex digits
	vkHex                      // identifiers, versions: hex/BCD digits as text
	vkText                     // LVAR text
	vkContainer                // LVAR data container, hex in wire order
	vkDate                     // type G only (primary VIF 6Ch)
	vkDateTime                 // types J, F, I, M by data field (VIF 6Dh)
	vkWhen                     // any date/time type by data field (VIFE "date of")
	vkDST                      // type K
	vkListen                   // type L
	vkSubDevice                // list of sub device types (6.5.2)
)

// vifTable identifies the table a VIF code came from.
type vifTable int

const (
	tPrimary vifTable = iota
	tFB               // alternate extension table (6.4.5)
	tFD               // main extension table (6.4.4.1)
	tFDFD             // second level extension table (6.4.4.2)
	tText             // plain-text VIF
	tOther            // any VIF, manufacturer VIF, reserved
)

type vifInfo struct {
	kind  vifKind
	exp   int // decimal exponent
	bin2  int // binary exponent (rating factors: 2^-12)
	text  string
	table vifTable
	code  byte // code within the table, extension bit cleared
	// nonMetric is 1 for combinable VIFE 3Dh (Annex C table C.1), 2 for
	// FCh 0Dh (table C.2).
	nonMetric int
	std       bool // combinable VIFE 1Dh: standard conform data content
}

func timeUnit(n byte) string { return [4]string{"s", "min", "h", "d"}[n&3] }

// longTimeUnit is the pp coding of table 12: hours to years.
func longTimeUnit(n byte) string { return [4]string{"h", "d", "mo", "a"}[n&3] }

func (r *Record) set(q, unit string, exp int, k vifKind) vifInfo {
	r.Quantity, r.Unit = q, unit
	return vifInfo{kind: k, exp: exp}
}

// primary is the primary VIF table (6.4.2, table 10).
func (r *Record) primary(c byte) vifInfo {
	v := r.primaryCode(c)
	v.table, v.code = tPrimary, c
	return v
}

func (r *Record) primaryCode(c byte) vifInfo {
	n := int(c & 0x07)
	nn := int(c & 0x03)
	switch {
	case c <= 0x07:
		return r.set("energy", "Wh", n-3, vkNumber)
	case c <= 0x0F:
		return r.set("energy", "J", n, vkNumber)
	case c <= 0x17:
		return r.set("volume", "m3", n-6, vkNumber)
	case c <= 0x1F:
		return r.set("mass", "kg", n-3, vkNumber)
	case c <= 0x23:
		return r.set("on_time", timeUnit(c), 0, vkNumber)
	case c <= 0x27:
		return r.set("operating_time", timeUnit(c), 0, vkNumber)
	case c <= 0x2F:
		return r.set("power", "W", n-3, vkNumber)
	case c <= 0x37:
		return r.set("power", "J/h", n, vkNumber)
	case c <= 0x3F:
		return r.set("volume_flow", "m3/h", n-6, vkNumber)
	case c <= 0x47:
		return r.set("volume_flow", "m3/min", n-7, vkNumber)
	case c <= 0x4F: // deprecated, decoded as formerly defined
		return r.set("volume_flow", "m3/s", n-9, vkNumber)
	case c <= 0x57: // deprecated, decoded as formerly defined
		return r.set("mass_flow", "kg/h", n-3, vkNumber)
	case c <= 0x5B:
		return r.set("flow_temperature", "Cel", nn-3, vkNumber)
	case c <= 0x5F:
		return r.set("return_temperature", "Cel", nn-3, vkNumber)
	case c <= 0x63:
		return r.set("temperature_difference", "K", nn-3, vkNumber)
	case c <= 0x67:
		return r.set("external_temperature", "Cel", nn-3, vkNumber)
	case c <= 0x6B:
		return r.set("pressure", "bar", nn-3, vkNumber)
	case c == 0x6C:
		return r.set("date", "", 0, vkDate)
	case c == 0x6D:
		return r.set("datetime", "", 0, vkDateTime)
	case c == 0x6E:
		return r.set("hca_units", "", 0, vkNumber)
	case c == 0x6F: // reserved for a third extension table
		return r.set("vif_6f", "", 0, vkNumber)
	case c <= 0x73:
		return r.set("averaging_duration", timeUnit(c), 0, vkNumber)
	case c <= 0x77:
		return r.set("actuality_duration", timeUnit(c), 0, vkNumber)
	case c == 0x78:
		return r.set("fabrication_number", "", 0, vkHex)
	case c == 0x79:
		return r.set("enhanced_id", "", 0, vkHex)
	case c == 0x7A:
		// 1 byte: link address (type C); 6 or 8 bytes: header identification.
		return r.set("bus_address", "", 0, vkUnsigned)
	}
	return r.set(fmt.Sprintf("vif_%02x", c), "", 0, vkNumber)
}

// fdTable is the main VIF extension table (VIF FDh, 6.4.4.1, table 12).
func (r *Record) fdTable(e byte) vifInfo {
	v := r.fdCode(e)
	v.table, v.code = tFD, e
	return v
}

func (r *Record) fdCode(e byte) vifInfo {
	nn := e & 0x03
	switch {
	case e <= 0x03:
		return r.set("credit", "", int(nn)-3, vkNumber)
	case e <= 0x07: // deprecated
		return r.set("debit", "", int(nn)-3, vkNumber)
	case e >= 0x24 && e <= 0x27:
		return r.set("storage_interval", timeUnit(e), 0, vkUnsigned)
	case e >= 0x2C && e <= 0x2F:
		return r.set("duration_since_readout", timeUnit(e), 0, vkUnsigned)
	case e >= 0x31 && e <= 0x33: // deprecated
		return r.set("tariff_duration", timeUnit(e), 0, vkUnsigned)
	case e >= 0x34 && e <= 0x37: // deprecated
		return r.set("tariff_period", timeUnit(e), 0, vkUnsigned)
	case e >= 0x3C && e <= 0x3F:
		return r.set("transmission_period", timeUnit(e), 0, vkUnsigned)
	case e >= 0x40 && e <= 0x4F:
		// 46h-4Ch are current; the others are deprecated codes decoded
		// with the formula they formerly had.
		return r.set("voltage", "V", int(e&0x0F)-9, vkNumber)
	case e >= 0x50 && e <= 0x5F:
		// 53h-5Ch are current; the others as formerly defined.
		return r.set("current", "A", int(e&0x0F)-12, vkNumber)
	case e >= 0x68 && e <= 0x6B:
		return r.set("duration_since_cumulation", longTimeUnit(e), 0, vkUnsigned)
	case e >= 0x6C && e <= 0x6F:
		return r.set("battery_operating_time", longTimeUnit(e), 0, vkUnsigned)
	}
	switch e {
	case 0x08: // unique message identification (formerly access number)
		return r.set("access_number", "", 0, vkUnsigned)
	case 0x09:
		return r.set("medium", "", 0, vkUnsigned)
	case 0x0A:
		return r.set("manufacturer", "", 0, vkHex)
	case 0x0B:
		return r.set("parameter_set", "", 0, vkHex)
	case 0x0C:
		return r.set("model_version", "", 0, vkHex)
	case 0x0D:
		return r.set("hardware_version", "", 0, vkHex)
	case 0x0E:
		return r.set("firmware_version", "", 0, vkHex)
	case 0x0F:
		return r.set("software_version", "", 0, vkHex)
	case 0x10:
		return r.set("customer_location", "", 0, vkHex)
	case 0x11:
		return r.set("customer", "", 0, vkHex)
	case 0x12: // deprecated
		return r.set("access_code_user", "", 0, vkHex)
	case 0x13: // deprecated
		return r.set("access_code_operator", "", 0, vkHex)
	case 0x14: // deprecated
		return r.set("access_code_system_operator", "", 0, vkHex)
	case 0x15: // deprecated
		return r.set("access_code_developer", "", 0, vkHex)
	case 0x16: // deprecated
		return r.set("password", "", 0, vkHex)
	case 0x17:
		return r.set("error_flags", "", 0, vkBits)
	case 0x18:
		return r.set("error_mask", "", 0, vkBits)
	case 0x19: // deprecated
		return r.set("security_key", "", 0, vkHex)
	case 0x1A:
		return r.set("digital_output", "", 0, vkBits)
	case 0x1B:
		return r.set("digital_input", "", 0, vkBits)
	case 0x1C:
		return r.set("baud_rate", "Bd", 0, vkUnsigned)
	case 0x1D: // deprecated
		return r.set("response_delay_time", "", 0, vkUnsigned)
	case 0x1E: // deprecated
		return r.set("retry", "", 0, vkUnsigned)
	case 0x1F:
		return r.set("remote_control", "", 0, vkBits)
	case 0x20:
		return r.set("first_storage_number", "", 0, vkUnsigned)
	case 0x21:
		return r.set("last_storage_number", "", 0, vkUnsigned)
	case 0x22:
		return r.set("storage_block_size", "", 0, vkUnsigned)
	case 0x23:
		return r.set("tariff_subunit_descriptor", "", 0, vkUnsigned)
	case 0x28:
		return r.set("storage_interval", "mo", 0, vkUnsigned)
	case 0x29:
		return r.set("storage_interval", "a", 0, vkUnsigned)
	case 0x2A:
		return r.set("operator_data", "", 0, vkHex)
	case 0x2B: // deprecated
		return r.set("time_point_second", "s", 0, vkUnsigned)
	case 0x30: // deprecated
		return r.set("tariff_start", "", 0, vkWhen)
	case 0x38: // deprecated
		return r.set("tariff_period", "mo", 0, vkUnsigned)
	case 0x39: // deprecated
		return r.set("tariff_period", "a", 0, vkUnsigned)
	case 0x3A:
		return r.set("dimensionless", "", 0, vkNumber)
	case 0x3B:
		return r.set("wmbus_container", "", 0, vkContainer)
	case 0x60:
		return r.set("reset_counter", "", 0, vkNumber)
	case 0x61:
		return r.set("cumulation_counter", "", 0, vkNumber)
	case 0x62:
		return r.set("control_signal", "", 0, vkNumber)
	case 0x63:
		return r.set("day_of_week", "", 0, vkUnsigned)
	case 0x64:
		return r.set("week_number", "", 0, vkUnsigned)
	case 0x65: // deprecated
		return r.set("day_change_time_point", "", 0, vkNumber)
	case 0x66:
		return r.set("parameter_activation_state", "", 0, vkUnsigned)
	case 0x67:
		return r.set("supplier_information", "", 0, vkUnsigned)
	case 0x70:
		return r.set("battery_change", "", 0, vkWhen)
	case 0x71:
		return r.set("rf_level", "dBm", 0, vkNumber)
	case 0x72:
		return r.set("daylight_savings", "", 0, vkDST)
	case 0x73:
		return r.set("listening_window", "", 0, vkListen)
	case 0x74:
		return r.set("battery_remaining", "d", 0, vkUnsigned)
	case 0x75:
		return r.set("meter_stop_count", "", 0, vkUnsigned)
	case 0x76:
		return r.set("manufacturer_container", "", 0, vkContainer)
	case 0x77:
		return r.set("upper_layer_container", "", 0, vkContainer)
	}
	return r.set(fmt.Sprintf("vif_fd%02x", e), "", 0, vkNumber)
}

// fdfdTable is the second level extension table (VIF FDh, VIFE FDh,
// 6.4.4.2, table 13).
func (r *Record) fdfdTable(e byte) vifInfo {
	v := r.fdfdCode(e)
	v.table, v.code = tFDFD, e
	return v
}

func (r *Record) fdfdCode(e byte) vifInfo {
	n := int(e & 1)
	switch e {
	case 0x00:
		return r.set("current_application", "", 0, vkHex)
	case 0x01:
		return r.set("sub_device_type", "", 0, vkSubDevice)
	case 0x02:
		return r.set("battery_remaining", "mo", 0, vkUnsigned)
	case 0x03:
		return r.set("battery_remaining", "a", 0, vkUnsigned)
	case 0x04:
		return r.set("local_comm_credits", "", 0, vkUnsigned)
	case 0x05:
		return r.set("wmbus_comm_credits", "", 0, vkUnsigned)
	case 0x08:
		return r.set("installation_conditions", "", 0, vkBits)
	case 0x10, 0x11:
		return r.set("co2", "[ppm]", n, vkNumber)
	case 0x12, 0x13:
		return r.set("co", "[ppm]", n, vkNumber)
	case 0x14, 0x15:
		return r.set("voc", "[ppb]", n, vkNumber)
	case 0x16:
		return r.set("voc", "ug/m3", 0, vkNumber)
	case 0x17:
		return r.set("particles", "ug/m3", 0, vkNumber)
	case 0x18:
		return r.set("pm1", "ug/m3", 0, vkNumber)
	case 0x19:
		return r.set("pm2_5", "ug/m3", 0, vkNumber)
	case 0x1A:
		return r.set("pm10", "ug/m3", 0, vkNumber)
	case 0x1B:
		return r.set("particle_count", "/m3", 5, vkNumber)
	case 0x1C:
		return r.set("pm1_count", "/m3", 5, vkNumber)
	case 0x1D:
		return r.set("pm2_5_count", "/m3", 5, vkNumber)
	case 0x1E:
		return r.set("pm10_count", "/m3", 5, vkNumber)
	case 0x1F:
		return r.set("illuminance", "lx", 0, vkNumber)
	case 0x20:
		return r.set("luminous_intensity", "cd", 0, vkNumber)
	case 0x21:
		return r.set("irradiance", "W/m2", 0, vkNumber)
	case 0x22:
		return r.set("wind_speed", "km/h", 0, vkNumber)
	case 0x23:
		return r.set("rainfall", "L/mm2", 0, vkNumber)
	case 0x24:
		return r.set("noise", "dBA", 0, vkNumber)
	case 0x25:
		return r.set("turbidity", "FNU", -2, vkNumber)
	case 0x27:
		return r.set("ph", "[pH]", -1, vkNumber)
	case 0x2C:
		return r.set("dismount_count", "", 0, vkUnsigned)
	case 0x2D:
		return r.set("test_button_count", "", 0, vkUnsigned)
	case 0x2E:
		return r.set("alarm_count", "", 0, vkUnsigned)
	case 0x2F:
		return r.set("alarm_mute_count", "", 0, vkUnsigned)
	case 0x30:
		return r.set("obstacle_count", "", 0, vkUnsigned)
	case 0x31:
		return r.set("smoke_entry_blocked_count", "", 0, vkUnsigned)
	case 0x32:
		return r.set("smoke_chamber_defect_count", "", 0, vkUnsigned)
	case 0x33:
		return r.set("selftest_failed_count", "", 0, vkUnsigned)
	case 0x34:
		return r.set("sounder_defect_count", "", 0, vkUnsigned)
	case 0x35:
		return r.set("co_alarm_low_count", "", 0, vkUnsigned)
	case 0x36:
		return r.set("co_alarm_medium_count", "", 0, vkUnsigned)
	case 0x37:
		return r.set("co_alarm_high_count", "", 0, vkUnsigned)
	case 0x38:
		return r.set("battery_status", "%", 0, vkUnsigned)
	case 0x39:
		return r.set("chamber_pollution", "%", 0, vkUnsigned)
	case 0x3A, 0x3B:
		return r.set("distance", "mm", n, vkNumber)
	case 0x3E:
		return r.set("moisture_level", "%", 0, vkNumber)
	case 0x3F:
		return r.set("approval_class", "", 0, vkText)
	case 0x40:
		return r.set("pressure_status", "", 0, vkBits)
	case 0x41:
		return r.set("smoke_alarm_status", "", 0, vkBits)
	case 0x42:
		return r.set("co_alarm_status", "", 0, vkBits)
	case 0x43:
		return r.set("heat_alarm_status", "", 0, vkBits)
	case 0x44:
		return r.set("door_window_status", "", 0, vkBits)
	}
	return r.set(fmt.Sprintf("vif_fdfd%02x", e), "", 0, vkNumber)
}

// fbTable is the alternate VIF extension table (VIF FBh, 6.4.5, table 15).
func (r *Record) fbTable(e byte) vifInfo {
	v := r.fbCode(e)
	v.table, v.code = tFB, e
	return v
}

func (r *Record) fbCode(e byte) vifInfo {
	n := int(e & 1)
	nn := int(e & 3)
	switch {
	case e <= 0x01:
		return r.set("energy", "MWh", n-1, vkNumber)
	case e <= 0x03:
		return r.set("reactive_energy", "kvarh", n, vkNumber)
	case e <= 0x05:
		return r.set("apparent_energy", "kVAh", n, vkNumber)
	case e == 0x06:
		return r.set("cop", "", -1, vkNumber)
	case e == 0x08 || e == 0x09:
		return r.set("energy", "GJ", n-1, vkNumber)
	case e >= 0x0C && e <= 0x0F:
		return r.set("energy", "Mcal", nn-1, vkNumber)
	case e == 0x10 || e == 0x11:
		return r.set("volume", "m3", n+2, vkNumber)
	case e >= 0x14 && e <= 0x17:
		return r.set("reactive_power", "kvar", nn-3, vkNumber)
	case e == 0x18 || e == 0x19:
		return r.set("mass", "t", n+2, vkUnsigned)
	case e == 0x1A || e == 0x1B:
		return r.set("relative_humidity", "%RH", n-1, vkUnsigned)
	case e == 0x20:
		return r.set("volume", "[ft_i]3", 0, vkNumber)
	case e == 0x21:
		return r.set("volume", "[ft_i]3", -1, vkNumber)
	case e == 0x23:
		return r.set("phase_i_u", "deg", -1, vkNumber)
	case e == 0x28 || e == 0x29:
		return r.set("power", "MW", n-1, vkNumber)
	case e == 0x2A:
		return r.set("phase_u_u", "deg", -1, vkNumber)
	case e == 0x2B:
		return r.set("phase_u_i", "deg", -1, vkNumber)
	case e >= 0x2C && e <= 0x2F:
		return r.set("frequency", "Hz", nn-3, vkNumber)
	case e == 0x30 || e == 0x31:
		return r.set("power", "GJ/h", n-1, vkNumber)
	case e >= 0x34 && e <= 0x37:
		return r.set("apparent_power", "kVA", nn-3, vkNumber)
	case e == 0x68:
		v := r.set("rating_factor_k", "/h", 0, vkUnsigned)
		v.bin2 = -12
		return v
	case e == 0x69:
		return r.set("rating_factor_kq", "W", 0, vkUnsigned)
	case e >= 0x6A && e <= 0x6D:
		v := r.set([4]string{"rating_factor_kc", "rating_factor_kcr", "rating_factor_kch", "rating_factor_kt"}[e-0x6A], "", 0, vkUnsigned)
		v.bin2 = -12
		return v
	case e == 0x6E:
		v := r.set("rating_factor_kd", "/kWh", 0, vkUnsigned)
		v.bin2 = -12
		return v
	case e >= 0x74 && e <= 0x77:
		return r.set("temperature_limit", "Cel", nn-3, vkNumber)
	case e >= 0x78:
		return r.set("cum_max_active_power", "W", int(e&7)-3, vkNumber)
	}
	return r.set(fmt.Sprintf("vif_fb%02x", e), "", 0, vkNumber)
}

// recordErrors are the record error codes of 6.4.8 (table 19), by VIFE
// code; "" marks codes that are not record errors.
var recordErrors = [0x20]string{
	0x00: "", 0x01: "too_many_difes", 0x02: "storage_not_implemented",
	0x03: "unit_not_implemented", 0x04: "tariff_not_implemented",
	0x05: "function_not_implemented", 0x06: "data_class_not_implemented",
	0x07: "data_size_not_implemented", 0x08: "reserved_08", 0x09: "reserved_09",
	0x0A: "reserved_0a", 0x0B: "too_many_vifes", 0x0C: "illegal_vif_group",
	0x0D: "illegal_vif_exponent", 0x0E: "vif_dif_mismatch", 0x0F: "unimplemented_action",
	0x15: "no_data", 0x16: "data_overflow", 0x17: "data_underflow", 0x18: "data_error",
	0x19: "reserved_19", 0x1A: "reserved_1a", 0x1B: "reserved_1b",
	0x1C: "premature_end",
}

// actions are the generalized object layer action codes (6.4.7, table
// 18), master to slave.
var actions = [16]string{"set", "add", "subtract", "or", "and", "xor", "and_not", "clear",
	"add_entry", "delete_entry", "delayed_action", "freeze", "add_to_readout",
	"delete_from_readout", "reserved", "get"}

// perUnits are the "per unit" combinable VIFEs 20h-35h (table 16): the
// modifier and the unit divisor.
var perUnits = map[byte][2]string{
	0x20: {"per_second", "s"}, 0x21: {"per_minute", "min"}, 0x22: {"per_hour", "h"},
	0x23: {"per_day", "d"}, 0x24: {"per_week", "wk"}, 0x25: {"per_month", "mo"},
	0x26: {"per_year", "a"}, 0x27: {"per_measurement", ""},
	0x28: {"per_input_pulse0", ""}, 0x29: {"per_input_pulse1", ""},
	0x2A: {"per_output_pulse0", ""}, 0x2B: {"per_output_pulse1", ""},
	0x2C: {"per_litre", "L"}, 0x2D: {"per_m3", "m3"}, 0x2E: {"per_kg", "kg"},
	0x2F: {"per_kelvin", "K"}, 0x30: {"per_kwh", "kWh"}, 0x31: {"per_gj", "GJ"},
	0x32: {"per_kw", "kW"}, 0x33: {"per_kelvin_litre", "(K.L)"}, 0x34: {"per_volt", "V"},
	0x35: {"per_ampere", "A"},
}

// fcModifiers are the extension of the combinable VIFE table (VIFE FCh,
// table 17).
var fcModifiers = map[byte]string{
	0x01: "l1", 0x02: "l2", 0x03: "l3", 0x04: "n", 0x05: "l2_l1", 0x06: "l3_l2",
	0x07: "l1_l3", 0x08: "q1", 0x09: "q2", 0x0A: "q3", 0x0B: "q4",
	0x0C: "import_export_delta", 0x0E: "secondary_sensor", 0x0F: "high_resolution",
	0x10: "absolute", 0x13: "end", 0x14: "to_meter", 0x15: "from_meter",
	0x16: "liquid", 0x17: "gas", 0x18: "outdoors", 0x25: "l1_l2", 0x26: "l2_l3",
	0x27: "l3_l1",
}

// subDeviceTypes are the sensor sub device types of 6.5.2 (table 20).
var subDeviceTypes = map[byte]string{
	1: "humidity", 2: "moisture", 3: "temperature", 5: "light", 6: "rainfall",
	7: "ph", 8: "anemometer", 9: "glass_break", 10: "door_window_contact",
	11: "door_window_lock", 12: "water_leakage", 13: "air_quality", 14: "co2",
	15: "turbidity", 18: "co_alarm", 19: "heat_alarm", 20: "smoke_alarm",
	21: "pressure", 22: "level", 23: "noise", 255: "other",
}

func subDeviceName(b byte) string {
	if s, ok := subDeviceTypes[b]; ok {
		return s
	}
	return fmt.Sprintf("reserved_%d", b)
}

// bitNames lists flag names per bit; "" bits are reserved or handled
// separately.
func setBits(x uint64, names []string) []string {
	var out []string
	for i, n := range names {
		if n != "" && x&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	return out
}

var (
	// Tables 21 to 24 (6.5.3).
	pressureBits = []string{"high_pressure", "low_pressure", "battery_low", "sensor_comm_error",
		"controller_restart", "mechanical_tamper", "", "mfct_bytes_following"}
	smokeBits = []string{"dismounted", "battery_low", "hw_sw_error", "smoke_sensor_fault",
		"sounder_fault_check_disabled", "obstacle_detection_disabled", "smoke_entry_detection_disabled",
		"smoke_alarm_enabled", "sounder_fault", "obstacle_detected", "smoke_entries_blocked",
		"smoke_alarm", "storage_state", "", "", "mfct_bytes_following"}
	coBits = []string{"dismounted", "battery_low", "hw_sw_error", "co_sensor_fault",
		"sounder_fault_check_disabled", "co_alarm_enabled", "", "", "sounder_fault", "co_alarm",
		"storage_state", "", "", "", "", "mfct_bytes_following"}
	heatBits = []string{"dismounted", "battery_low", "hw_sw_error", "storage_state",
		"heat_sensor_fault", "alarm_static_temperature", "alarm_rate_of_rise", "heat_alarm",
		"sounder_test_unavailable", "sounder_fault", "", "", "", "", "", "mfct_bytes_following"}
	// Annex E.1, tables E.2, E.4, E.6: one list per error byte (bit 7:
	// another standardized byte follows).
	errorFlagBytes = [3][]string{
		{"mechanical_tamper", "battery_low", "external_alarm", "battery_cut", "hw_sw_error",
			"connection_interrupt", "magnetic_tamper"},
		{"unauthorised_access", "credit_limit_exceeded", "leakage", "no_flow",
			"consumption_out_of_range", "sensor_out_of_range", "clock_sync_error"},
		{"hist_mechanical_tamper", "hist_magnetic_tamper", "hist_connection_interrupt",
			"hist_external_alarm", "hist_leakage", "hist_no_flow", "hist_sensor_out_of_range"},
	}
)

// flags decodes the symbolic meaning of bit-field and enumerated data
// (6.5, annex C.3, annex E), or nil.
func (v vifInfo) flags(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var x uint64
	for i := len(b) - 1; i >= 0 && i < 8; i-- {
		x = x<<8 | uint64(b[i])
	}
	switch v.table {
	case tFD:
		switch v.code {
		case 0x17:
			if !v.std {
				return nil
			}
			var out []string
			for i := 0; i < len(b) && i < 3; i++ {
				out = append(out, setBits(uint64(b[i]), errorFlagBytes[i])...)
				if b[i]&0x80 == 0 {
					break
				}
			}
			return out
		case 0x1F:
			return remoteControl(b[0], v.std)
		}
	case tFDFD:
		switch v.code {
		case 0x08:
			return installation(b[0])
		case 0x40:
			return setBits(x, pressureBits)
		case 0x41:
			return setBits(x, smokeBits)
		case 0x42:
			out := setBits(x, coBits)
			if l := x >> 6 & 3; l > 0 {
				out = append(out, [4]string{"", "co_level_50ppm", "co_level_100ppm", "co_level_300ppm"}[l])
			}
			return out
		case 0x43:
			return setBits(x, heatBits)
		case 0x44:
			var out []string
			if s := [4]string{"closed", "open", "contact_unknown", ""}[x&3]; s != "" {
				out = append(out, s)
			}
			if s := [4]string{"locked", "unlocked", "lock_unknown", ""}[x>>2&3]; s != "" {
				out = append(out, s)
			}
			if x&0x80 != 0 {
				out = append(out, "mfct_bytes_following")
			}
			return out
		}
	}
	return nil
}

// remoteControl decodes the least significant remote control byte: table
// C.4 (valve), or with the standard-conform VIFE the RC1 bits of annex
// E.2.
func remoteControl(b byte, std bool) []string {
	if !std {
		switch b {
		case 0:
			return []string{"valve_closed"}
		case 1:
			return []string{"valve_opened"}
		case 2:
			return []string{"valve_released"}
		}
		return []string{fmt.Sprintf("reserved_%d", b)}
	}
	var out []string
	if b&1 != 0 {
		if b&2 != 0 {
			out = append(out, "power_increase")
		} else {
			out = append(out, "power_decrease")
		}
	}
	// Table E.9 lists b3 as the most significant bit of the test mode.
	switch int(b>>3&1)<<2 | int(b>>4&1)<<1 | int(b>>5&1) {
	case 1:
		out = append(out, "test_emit_zeros")
	case 2:
		out = append(out, "test_emit_0101")
	case 3:
		out = append(out, "test_emit_carrier")
	case 4:
		out = append(out, "test_emit_ones")
	case 5:
		out = append(out, "test_reception")
	}
	if b&0x40 != 0 {
		out = append(out, "normal_mode")
	} else {
		out = append(out, "power_save_mode")
	}
	return out
}

// installation decodes the installation conditions byte (table 14).
func installation(b byte) []string {
	var out []string
	if b&0x80 != 0 {
		out = append(out, "standard_conditions_byte")
	}
	if s := [4]string{"", "volume_display_no_prefix", "volume_display_k", ""}[b>>5&3]; s != "" {
		out = append(out, s)
	}
	if p := b >> 2 & 7; p >= 1 && p <= 4 {
		out = append(out, [5]string{"", "energy_display_no_prefix", "energy_display_k", "energy_display_m", "energy_display_g"}[p])
	}
	if s := [4]string{"", "flow_pipe", "return_pipe", ""}[b&3]; s != "" {
		out = append(out, s)
	}
	return out
}

// nonMetricUnit substitutes the unit of a primary VIF (and the cold/warm
// temperature limit) per annex C tables C.1 (alt 1) and C.2 (alt 2),
// returning the new unit and the exponent change.
func nonMetricUnit(v vifInfo, alt int) (string, int, bool) {
	gal := "[gal_us]"
	if alt == 2 {
		gal = "[gal_br]"
	}
	if v.table == tFB && v.code >= 0x74 && v.code <= 0x77 && alt == 1 {
		return "[degF]", 0, true
	}
	if v.table != tPrimary {
		return "", 0, false
	}
	c := v.code
	switch {
	case c >= 0x10 && c <= 0x17: // volume: m3 → litre-based gallons
		return gal, 3, true
	case c >= 0x38 && c <= 0x3F:
		return gal + "/h", 3, true
	case c >= 0x40 && c <= 0x47:
		return gal + "/min", 3, true
	case c >= 0x48 && c <= 0x4F:
		return gal + "/s", 3, true
	}
	if alt != 1 {
		return "", 0, false
	}
	switch {
	case c <= 0x07: // Wh → kBTU
		return "[Btu_IT]", 3, true
	case c >= 0x28 && c <= 0x2F: // W → mBTU/s
		return "[Btu_IT]/s", -3, true
	case c >= 0x58 && c <= 0x67: // flow, return, difference, external temperature
		return "[degF]", 0, true
	}
	return "", 0, false
}
