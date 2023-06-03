import logging

from . import JNISimProcedure
from ...api_record import add_to_records


l = logging.getLogger(__name__)

class GetEnv(JNISimProcedure):

    return_ty = 'int'

    def run(self, jvm, env, version):
        # resolve env to concrete values
        env_results = self.resolve_arg(env, 'pointer')
        if len(env_results) != 1:
            l.error("GetEnv: penv cannot resolve to single address!!!")

        jenv_ptr = self.get_global_map().get('jenv_ptr')
        if not jenv_ptr:
            raise JNIEnvMissingError('"jenv_ptr" is not stored in project. ')

        for env_concrete in env_results:
            assert type(env_concrete) == int
            self._store_in_native_memory(data=jenv_ptr,
                                            data_type='long',
                                            addr=env_concrete)

        version = self.resolve_arg(version, 'int')
        add_to_records(self.get_callsite(), type(self).__name__, (None, env_results, version))
        return self.JNI_OK


class JNIEnvMissingError(Exception):
    pass

