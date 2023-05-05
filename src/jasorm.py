import datetime
import json
import traceback
import collections

import pymysql
import pymysql.cursors
import pymysql.constants
import pymysql.converters
import pymysql.connections

import sqlite3

QueryResp = collections.namedtuple('QueryResp', ['rowcount', 'lastrowid'])

def datetime_adapter( d ):
    return d.strftime('%Y-%m-%d %H:%M:%S')

sqlite3.register_adapter(datetime.datetime, datetime_adapter)

pymysql.converters.conversions[pymysql.constants.FIELD_TYPE.JSON] = json.loads

def escapeDict( s, charset, mapping=None ):
    return pymysql.converters.encoders[str](json.dumps(s, ensure_ascii=False), mapping)
    
pymysql.converters.encoders[dict] = escapeDict
pymysql.converters.conversions[dict] = escapeDict

paramchrmap = {
    'qmark' : '?',
    'pyformat': '%s',
}
    
class SqlExpr(object):
    
    def __init__( self, bc, db ):
        
        self.bc = bc
        self.db = db
        
        self.expr = {}
        
        return
    
    def append( self, data ):
        
        if not data :
            return
        
        ks, vs = zip(* data.items() )
        
        sql = '''insert into {} ({}) values ({})'''.format(
            self.db,
            ','.join([ '`%s`' % k for k in ks ]),
            ','.join([ self.bc.paramchr ]*len(vs)),
        )
        
        return self.bc.execute(sql, vs)
    
    def select( self ):
        
        sql = 'select * from {}'.format(self.db)
        
        return self.bc.execute(sql, ())
    

class Jasorm(object):
    
    def __init__( self, dbtype, config ):
        
        self.__bc = {
            'sqlite': SqliteBC,
            'mysql': MySqlBC,
        }[dbtype](**config)
        
        return
    
    def __getattr__( self, db ):
        return SqlExpr(self.__bc, db)
    
    def __call__( self, sql, args=() ):
        return self.__bc.execute(sql, args)
    

# threadsafety Meaning
#   0  Threads may not share the module.
#   1  Threads may share the module, but not connections.
#   2  Threads may share the module and connections.
#   3  Threads may share the module, connections and cursors.

class SqliteBC(object):
    
    # threadsafety 3
    
    paramchr = paramchrmap[sqlite3.paramstyle]
    
    def __init__( self, path ):
        
        self.path = path
        self.con = sqlite3.connect(self.path)
        
        return
    
    def execute( self, sql, args, cursortype=None ):
        
        #print(sql, args)
        cur = self.con.cursor()
        cur.row_factory=self.dict_factory
        
        x = cur.execute(sql, args)
        
        #print('   -',cur.description)
        #print('   -',cur.rowcount)
        #print('   -',cur.lastrowid)
        
        if cur.description :
            r = cur.fetchall()
        else :
            r = QueryResp(cur.rowcount, cur.lastrowid)
            self.con.commit()
        
        return r
    
    @staticmethod
    def dict_factory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d
    

class MySqlBC(object):
    
    # threadsafety 1
    
    paramchr = paramchrmap[pymysql.paramstyle]
    
    default_dbargs = {
        'charset': 'utf8mb4',
        'cursorclass': pymysql.cursors.DictCursor,
        'connect_timeout': 3.0,
        'autocommit': True
    }
    
    conn_retry = 3
    
    def __init__( self, host, port, user, passwd, db ):
        
        self.db_args = {
            "host":host,
            "port":port,
            "user":user,
            "passwd":passwd,
            "db":db,
        }
        
        self.con = None
        
        return
    
    def make_conn( self ):
        
        return pymysql.connect(
            
            **self.db_args,
            **self.default_dbargs,
        )
    
    def execute(self, sql, args, cursortype=None):

        ee = None
        exc = ''
        
        conn = self.con if self.con else self.make_conn()
        
        for i in range(self.conn_retry):

            try:
                
                with conn.cursor(pymysql.cursors.DictCursor) as csr:
                    csr.execute(sql, args)
                    #print(csr._result.fields)
                    if csr.description:
                        #for f in csr._result.fields:
                        #    print('catalog   :',f.catalog)
                        #    print('db        :',f.db)
                        #    print('table_name:',f.table_name)
                        #    print('org_table :',f.org_table)
                        #    print('name      :',f.name)
                        #    print('org_name  :',f.org_name)
                        #    print('charsetnr :',f.charsetnr)
                        #    print('length    :',f.length)
                        #    print('type_code :',f.type_code)
                        #    print('flags     :',f.flags)
                        #    print('scale     :',f.scale)
                        #    print('----------------------------')
                        r = csr.fetchall()
                    else:
                        r = QueryResp(csr.rowcount, csr.lastrowid)
                
                self.con = conn
                
                return r

            except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
                
                conn = self.make_conn()
                
                exc = traceback.format_exc()
                ee = e
            
            finally:

                pass
        
        self.con = None
        
        if ee == None:
            print(exc)
            raise Exception('can not be reach here.')

        raise ee


