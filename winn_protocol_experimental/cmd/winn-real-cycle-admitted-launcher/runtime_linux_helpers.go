//go:build linux

package main

import (
	"io"
	"os"
	"reflect"
)

func ioReadFull(reader io.Reader, data []byte) (int, error) {
	return io.ReadFull(reader, data)
}

func ioCopy(writer io.Writer, reader io.Reader) (int64, error) {
	return io.Copy(writer, reader)
}

func ioMultiWriter(writers ...io.Writer) io.Writer {
	return io.MultiWriter(writers...)
}

func ioLimitReader(reader io.Reader, limit int64) io.Reader {
	return io.LimitReader(reader, limit)
}

func descriptorNlink(info os.FileInfo) uint64 {
	return statUintField(info, "Nlink")
}

func descriptorUID(info os.FileInfo) uint64 {
	return statUintField(info, "Uid")
}

func statUintField(info os.FileInfo, name string) uint64 {
	if info == nil {
		return 0
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName(name)
	if !field.IsValid() {
		return 0
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return field.Uint()
	default:
		return 0
	}
}
