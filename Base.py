import logging
import os
import time



class BaseTarget(object):
    '''
    Basic class to ease logging and description of objects.
    '''
    _logger = None
    log_file_name = './logs/%s.log' % (time.strftime("%Y%m%d-%H%M%S"),)

    @classmethod
    def get_logger(cls):
        '''
        :return: the class logger
        '''
        if BaseTarget._logger is None:
            logger = logging.getLogger('target')
            logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            logger.addHandler(consolehandler)
            if not os.path.exists('./logs'):
                os.mkdir('./logs')
            filehandler = logging.FileHandler(BaseTarget.log_file_name)
            file_format = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(module)s.%(funcName)s] -> %(message)s')
            filehandler.setFormatter(file_format)
            logger.addHandler(filehandler)
            BaseTarget._logger = logger
        return BaseTarget._logger

    @classmethod
    def get_log_file_name(cls):
        '''
        :return: log file name
        '''
        return BaseTarget.log_file_name

    @classmethod
    def set_verbosity(cls, verbosity):
        '''
        Set verbosity of logger

        :param verbosity: verbosity level. currently, we only support 1 (logging.DEBUG)
        '''
        if verbosity > 0:
            # currently, we only toggle between INFO, DEBUG
            logger = BaseTarget.get_logger()
            levels = [logging.DEBUG]
            verbosity = min(verbosity, len(levels)) - 1
            logger.setLevel(levels[verbosity])

    def __init__(self, name, logger=None):
        '''
        :param name: name of the object
        '''
        self.name = name
        if logger:
            self.logger = logger
        else:
            self.logger = BaseTarget.get_logger()

    def not_implemented(self, func_name):
        '''
        log access to unimplemented method and raise error

        :param func_name: name of unimplemented function.
        :raise: NotImplementedError detailing the function the is not implemented.
        '''
        msg = '%s is not overridden by %s' % (func_name, type(self).__name__)
        self.logger.error(msg)
        raise NotImplementedError(msg)

    def get_description(self):
        '''
        :rtype: str
        :return: the description of the object. by default only prints the object type.
        '''
        return type(self).__name__

    def get_name(self):
        '''
        :rtype: str
        :return: object's name
        '''
        return self.name
