from __future__ import annotations

from ._pyfwht import *  # noqa: F401,F403
from ._pyfwht import Config, Context as _NativeContext, default_config


class Context:
	"""Compatibility wrapper exposing the high-level context API expected by callers."""

	def __init__(
		self,
		config: Config | None = None,
		*,
		backend=None,
		num_threads: int | None = None,
		gpu_device: int | None = None,
		normalize: bool | None = None,
	) -> None:
		if config is None:
			config = default_config()
		if backend is not None:
			config.backend = backend
		if num_threads is not None:
			config.num_threads = num_threads
		if gpu_device is not None:
			config.gpu_device = gpu_device
		if normalize is not None:
			config.normalize = normalize
		self._context = _NativeContext(config)

	def transform(self, data):
		dtype_name = getattr(getattr(data, "dtype", None), "name", None)
		if dtype_name == "float64":
			self._context.transform_f64(data)
			return data
		if dtype_name == "int32":
			self._context.transform_i32(data)
			return data
		raise TypeError("Context.transform supports only float64 and int32 arrays")

	def transform_f64(self, data):
		self._context.transform_f64(data)
		return data

	def transform_i32(self, data):
		self._context.transform_i32(data)
		return data

	def close(self) -> None:
		self._context.close()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, tb) -> bool:
		self.close()
		return False
