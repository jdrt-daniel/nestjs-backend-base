PGDMP  +    2                }            database_db    16.4    17.4 �    g           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                           false            h           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                           false            i           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                           false            j           1262    47049    database_db    DATABASE     ~   CREATE DATABASE database_db WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'Spanish_Spain.1252';
    DROP DATABASE database_db;
                     postgres    false                        2615    47052    parametricas    SCHEMA        CREATE SCHEMA parametricas;
    DROP SCHEMA parametricas;
                     postgres    false                        2615    47050    proyecto    SCHEMA        CREATE SCHEMA proyecto;
    DROP SCHEMA proyecto;
                     postgres    false                        2615    47051    usuarios    SCHEMA        CREATE SCHEMA usuarios;
    DROP SCHEMA usuarios;
                     postgres    false            �            1259    47146 
   parametros    TABLE     �  CREATE TABLE parametricas.parametros (
    _estado character varying(30) NOT NULL,
    _transaccion character varying(30) NOT NULL,
    _usuario_creacion bigint NOT NULL,
    _fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    _usuario_modificacion bigint,
    _fecha_modificacion timestamp without time zone DEFAULT now(),
    id bigint NOT NULL,
    codigo character varying(15) NOT NULL,
    nombre character varying(50) NOT NULL,
    grupo character varying(15) NOT NULL,
    descripcion character varying(255) NOT NULL,
    CONSTRAINT "CHK_7a005c8ef43eb2a8110c36d732" CHECK (((_estado)::text = ANY ((ARRAY['ACTIVO'::character varying, 'INACTIVO'::character varying])::text[])))
);
 $   DROP TABLE parametricas.parametros;
       parametricas         heap r       postgres    false    8            k           0    0    COLUMN parametros._estado    COMMENT     L   COMMENT ON COLUMN parametricas.parametros._estado IS 'Estado del registro';
          parametricas               postgres    false    233            l           0    0    COLUMN parametros._transaccion    COMMENT     Z   COMMENT ON COLUMN parametricas.parametros._transaccion IS 'Tipo de operación ejecutada';
          parametricas               postgres    false    233            m           0    0 #   COLUMN parametros._usuario_creacion    COMMENT     f   COMMENT ON COLUMN parametricas.parametros._usuario_creacion IS 'Id de usuario que creó el registro';
          parametricas               postgres    false    233            n           0    0 !   COLUMN parametros._fecha_creacion    COMMENT     S   COMMENT ON COLUMN parametricas.parametros._fecha_creacion IS 'Fecha de creación';
          parametricas               postgres    false    233            o           0    0 '   COLUMN parametros._usuario_modificacion    COMMENT     r   COMMENT ON COLUMN parametricas.parametros._usuario_modificacion IS 'Id de usuario que realizo una modificación';
          parametricas               postgres    false    233            p           0    0 %   COLUMN parametros._fecha_modificacion    COMMENT     o   COMMENT ON COLUMN parametricas.parametros._fecha_modificacion IS 'Fecha en que se realizó una modificación';
          parametricas               postgres    false    233            q           0    0    COLUMN parametros.id    COMMENT     Y   COMMENT ON COLUMN parametricas.parametros.id IS 'Clave primaria de la tabla Parámetro';
          parametricas               postgres    false    233            r           0    0    COLUMN parametros.codigo    COMMENT     M   COMMENT ON COLUMN parametricas.parametros.codigo IS 'Código de parámetro';
          parametricas               postgres    false    233            s           0    0    COLUMN parametros.nombre    COMMENT     L   COMMENT ON COLUMN parametricas.parametros.nombre IS 'Nombre de parámetro';
          parametricas               postgres    false    233            t           0    0    COLUMN parametros.grupo    COMMENT     J   COMMENT ON COLUMN parametricas.parametros.grupo IS 'Grupo de parámetro';
          parametricas               postgres    false    233            u           0    0    COLUMN parametros.descripcion    COMMENT     W   COMMENT ON COLUMN parametricas.parametros.descripcion IS 'Descripción de parámetro';
          parametricas               postgres    false    233            �            1259    47145    parametros_id_seq    SEQUENCE     �   CREATE SEQUENCE parametricas.parametros_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE parametricas.parametros_id_seq;
       parametricas               postgres    false    233    8            v           0    0    parametros_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE parametricas.parametros_id_seq OWNED BY parametricas.parametros.id;
          parametricas               postgres    false    232            �            1259    47054 
   migrations    TABLE     �   CREATE TABLE proyecto.migrations (
    id integer NOT NULL,
    "timestamp" bigint NOT NULL,
    name character varying NOT NULL
);
     DROP TABLE proyecto.migrations;
       proyecto         heap r       postgres    false    6            �            1259    47053    migrations_id_seq    SEQUENCE     �   CREATE SEQUENCE proyecto.migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE proyecto.migrations_id_seq;
       proyecto               postgres    false    6    219            w           0    0    migrations_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE proyecto.migrations_id_seq OWNED BY proyecto.migrations.id;
          proyecto               postgres    false    218            �            1259    47137    session    TABLE     �   CREATE TABLE proyecto.session (
    "expiredAt" bigint NOT NULL,
    id character varying(255) NOT NULL,
    "json" text NOT NULL,
    "destroyedAt" timestamp without time zone
);
    DROP TABLE proyecto.session;
       proyecto         heap r       postgres    false    6            x           0    0    COLUMN session."expiredAt"    COMMENT     U   COMMENT ON COLUMN proyecto.session."expiredAt" IS 'Fecha de expiración de sesión';
          proyecto               postgres    false    231            y           0    0    COLUMN session.id    COMMENT     =   COMMENT ON COLUMN proyecto.session.id IS 'Id de la sesión';
          proyecto               postgres    false    231            z           0    0    COLUMN session."json"    COMMENT     [   COMMENT ON COLUMN proyecto.session."json" IS 'Información de la sesión en formato json';
          proyecto               postgres    false    231            {           0    0    COLUMN session."destroyedAt"    COMMENT     a   COMMENT ON COLUMN proyecto.session."destroyedAt" IS 'Fecha de eliminación o cierre de sesión';
          proyecto               postgres    false    231            �            1259    47129    casbin_rule    TABLE       CREATE TABLE usuarios.casbin_rule (
    id integer NOT NULL,
    ptype character varying,
    v0 character varying,
    v1 character varying,
    v2 character varying,
    v3 character varying,
    v4 character varying,
    v5 character varying,
    v6 character varying
);
 !   DROP TABLE usuarios.casbin_rule;
       usuarios         heap r       postgres    false    7            |           0    0    COLUMN casbin_rule.id    COMMENT     V   COMMENT ON COLUMN usuarios.casbin_rule.id IS 'Clave primaria de la tabla CasbinRule';
          usuarios               postgres    false    230            }           0    0    COLUMN casbin_rule.ptype    COMMENT     K   COMMENT ON COLUMN usuarios.casbin_rule.ptype IS 'Tipo de política (p,g)';
          usuarios               postgres    false    230            ~           0    0    COLUMN casbin_rule.v0    COMMENT     H   COMMENT ON COLUMN usuarios.casbin_rule.v0 IS 'Regla de acceso (roles)';
          usuarios               postgres    false    230                       0    0    COLUMN casbin_rule.v1    COMMENT     H   COMMENT ON COLUMN usuarios.casbin_rule.v1 IS 'Regla de acceso (rutas)';
          usuarios               postgres    false    230            �           0    0    COLUMN casbin_rule.v2    COMMENT     �   COMMENT ON COLUMN usuarios.casbin_rule.v2 IS 'Regla de acceso (GET, POST, PATCH, DELETE para backend y read, update, create y delete para frontend)';
          usuarios               postgres    false    230            �           0    0    COLUMN casbin_rule.v3    COMMENT     T   COMMENT ON COLUMN usuarios.casbin_rule.v3 IS 'Regla de acceso (Backend, Frontend)';
          usuarios               postgres    false    230            �           0    0    COLUMN casbin_rule.v4    COMMENT     @   COMMENT ON COLUMN usuarios.casbin_rule.v4 IS 'Regla de acceso';
          usuarios               postgres    false    230            �           0    0    COLUMN casbin_rule.v5    COMMENT     @   COMMENT ON COLUMN usuarios.casbin_rule.v5 IS 'Regla de acceso';
          usuarios               postgres    false    230            �           0    0    COLUMN casbin_rule.v6    COMMENT     @   COMMENT ON COLUMN usuarios.casbin_rule.v6 IS 'Regla de acceso';
          usuarios               postgres    false    230            �            1259    47128    casbin_rule_id_seq    SEQUENCE     �   CREATE SEQUENCE usuarios.casbin_rule_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE usuarios.casbin_rule_id_seq;
       usuarios               postgres    false    7    230            �           0    0    casbin_rule_id_seq    SEQUENCE OWNED BY     M   ALTER SEQUENCE usuarios.casbin_rule_id_seq OWNED BY usuarios.casbin_rule.id;
          usuarios               postgres    false    229            �            1259    47158    modulos    TABLE     �  CREATE TABLE usuarios.modulos (
    _estado character varying(30) NOT NULL,
    _transaccion character varying(30) NOT NULL,
    _usuario_creacion bigint NOT NULL,
    _fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    _usuario_modificacion bigint,
    _fecha_modificacion timestamp without time zone DEFAULT now(),
    id bigint NOT NULL,
    label character varying(50) NOT NULL,
    url character varying(50) NOT NULL,
    nombre character varying(50) NOT NULL,
    propiedades jsonb NOT NULL,
    id_modulo bigint,
    CONSTRAINT "CHK_6e5c7c292e38b5d7cdc9217557" CHECK (((_estado)::text = ANY ((ARRAY['ACTIVO'::character varying, 'INACTIVO'::character varying])::text[])))
);
    DROP TABLE usuarios.modulos;
       usuarios         heap r       postgres    false    7            �           0    0    COLUMN modulos._estado    COMMENT     E   COMMENT ON COLUMN usuarios.modulos._estado IS 'Estado del registro';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos._transaccion    COMMENT     S   COMMENT ON COLUMN usuarios.modulos._transaccion IS 'Tipo de operación ejecutada';
          usuarios               postgres    false    235            �           0    0     COLUMN modulos._usuario_creacion    COMMENT     _   COMMENT ON COLUMN usuarios.modulos._usuario_creacion IS 'Id de usuario que creó el registro';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos._fecha_creacion    COMMENT     L   COMMENT ON COLUMN usuarios.modulos._fecha_creacion IS 'Fecha de creación';
          usuarios               postgres    false    235            �           0    0 $   COLUMN modulos._usuario_modificacion    COMMENT     k   COMMENT ON COLUMN usuarios.modulos._usuario_modificacion IS 'Id de usuario que realizo una modificación';
          usuarios               postgres    false    235            �           0    0 "   COLUMN modulos._fecha_modificacion    COMMENT     h   COMMENT ON COLUMN usuarios.modulos._fecha_modificacion IS 'Fecha en que se realizó una modificación';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos.id    COMMENT     O   COMMENT ON COLUMN usuarios.modulos.id IS 'Clave primaria de la tabla Módulo';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos.label    COMMENT     a   COMMENT ON COLUMN usuarios.modulos.label IS 'Etiqueta del módulo para el Sidebar del proyecto';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos.url    COMMENT     J   COMMENT ON COLUMN usuarios.modulos.url IS 'Ruta para acceder al módulo';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos.nombre    COMMENT     C   COMMENT ON COLUMN usuarios.modulos.nombre IS 'Nombre del módulo';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos.propiedades    COMMENT     p   COMMENT ON COLUMN usuarios.modulos.propiedades IS 'Propiedades definidas del módulo, como orden, icono, etc.';
          usuarios               postgres    false    235            �           0    0    COLUMN modulos.id_modulo    COMMENT     k   COMMENT ON COLUMN usuarios.modulos.id_modulo IS 'Clave foránea que índica que pertenece a otro módulo';
          usuarios               postgres    false    235            �            1259    47157    modulos_id_seq    SEQUENCE     y   CREATE SEQUENCE usuarios.modulos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE usuarios.modulos_id_seq;
       usuarios               postgres    false    235    7            �           0    0    modulos_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE usuarios.modulos_id_seq OWNED BY usuarios.modulos.id;
          usuarios               postgres    false    234            �            1259    47063    personas    TABLE     I  CREATE TABLE usuarios.personas (
    _estado character varying(30) NOT NULL,
    _transaccion character varying(30) NOT NULL,
    _usuario_creacion bigint NOT NULL,
    _fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    _usuario_modificacion bigint,
    _fecha_modificacion timestamp without time zone DEFAULT now(),
    id bigint NOT NULL,
    uuid_ciudadano uuid,
    nombres character varying(100),
    primer_apellido character varying(100),
    segundo_apellido character varying(100),
    tipo_documento character varying(15) DEFAULT 'CI'::character varying NOT NULL,
    tipo_documento_otro character varying(50),
    nro_documento character varying(50) NOT NULL,
    fecha_nacimiento date,
    telefono character varying(50),
    genero character varying(15),
    observacion character varying(255),
    CONSTRAINT "CHK_5bf623e988eda9f1ee56b49581" CHECK (((_estado)::text = ANY ((ARRAY['ACTIVO'::character varying, 'INACTIVO'::character varying])::text[]))),
    CONSTRAINT "CHK_762e4eaa6cf745f33298dfbd4c" CHECK (((tipo_documento)::text = ANY ((ARRAY['CI'::character varying, 'PASAPORTE'::character varying, 'OTRO'::character varying])::text[]))),
    CONSTRAINT "CHK_cf88805ad4a3aec7b9e04bbc58" CHECK (((genero)::text = ANY ((ARRAY['M'::character varying, 'F'::character varying, 'OTRO'::character varying])::text[])))
);
    DROP TABLE usuarios.personas;
       usuarios         heap r       postgres    false    7            �           0    0    COLUMN personas._estado    COMMENT     F   COMMENT ON COLUMN usuarios.personas._estado IS 'Estado del registro';
          usuarios               postgres    false    221            �           0    0    COLUMN personas._transaccion    COMMENT     T   COMMENT ON COLUMN usuarios.personas._transaccion IS 'Tipo de operación ejecutada';
          usuarios               postgres    false    221            �           0    0 !   COLUMN personas._usuario_creacion    COMMENT     `   COMMENT ON COLUMN usuarios.personas._usuario_creacion IS 'Id de usuario que creó el registro';
          usuarios               postgres    false    221            �           0    0    COLUMN personas._fecha_creacion    COMMENT     M   COMMENT ON COLUMN usuarios.personas._fecha_creacion IS 'Fecha de creación';
          usuarios               postgres    false    221            �           0    0 %   COLUMN personas._usuario_modificacion    COMMENT     l   COMMENT ON COLUMN usuarios.personas._usuario_modificacion IS 'Id de usuario que realizo una modificación';
          usuarios               postgres    false    221            �           0    0 #   COLUMN personas._fecha_modificacion    COMMENT     i   COMMENT ON COLUMN usuarios.personas._fecha_modificacion IS 'Fecha en que se realizó una modificación';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.id    COMMENT     P   COMMENT ON COLUMN usuarios.personas.id IS 'Clave primaria de la tabla Persona';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.uuid_ciudadano    COMMENT     U   COMMENT ON COLUMN usuarios.personas.uuid_ciudadano IS 'UUID de Ciudadanía Digital';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.nombres    COMMENT     G   COMMENT ON COLUMN usuarios.personas.nombres IS 'Nombre de la persona';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.primer_apellido    COMMENT     X   COMMENT ON COLUMN usuarios.personas.primer_apellido IS 'Primer apellido de la persona';
          usuarios               postgres    false    221            �           0    0     COLUMN personas.segundo_apellido    COMMENT     Z   COMMENT ON COLUMN usuarios.personas.segundo_apellido IS 'Segundo apellido de la persona';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.tipo_documento    COMMENT     p   COMMENT ON COLUMN usuarios.personas.tipo_documento IS 'Tipo de documento de la persona (CI, Pasaporte, otros)';
          usuarios               postgres    false    221            �           0    0 #   COLUMN personas.tipo_documento_otro    COMMENT     n   COMMENT ON COLUMN usuarios.personas.tipo_documento_otro IS 'Otro tipo de documento de la persona, si existe';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.nro_documento    COMMENT     [   COMMENT ON COLUMN usuarios.personas.nro_documento IS 'Número de documento de la persona';
          usuarios               postgres    false    221            �           0    0     COLUMN personas.fecha_nacimiento    COMMENT     ]   COMMENT ON COLUMN usuarios.personas.fecha_nacimiento IS 'Fecha de nacimiento de la persona';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.telefono    COMMENT     K   COMMENT ON COLUMN usuarios.personas.telefono IS 'Teléfono de la persona';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.genero    COMMENT     G   COMMENT ON COLUMN usuarios.personas.genero IS 'Género de la persona';
          usuarios               postgres    false    221            �           0    0    COLUMN personas.observacion    COMMENT     �   COMMENT ON COLUMN usuarios.personas.observacion IS 'Observación, información relevante no definida en los campos establecidos referentes a la persona';
          usuarios               postgres    false    221            �            1259    47062    personas_id_seq    SEQUENCE     z   CREATE SEQUENCE usuarios.personas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE usuarios.personas_id_seq;
       usuarios               postgres    false    221    7            �           0    0    personas_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE usuarios.personas_id_seq OWNED BY usuarios.personas.id;
          usuarios               postgres    false    220            �            1259    47121    refresh_tokens    TABLE       CREATE TABLE usuarios.refresh_tokens (
    id character varying NOT NULL,
    grant_id character varying NOT NULL,
    iat timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    is_revoked boolean NOT NULL,
    data jsonb NOT NULL
);
 $   DROP TABLE usuarios.refresh_tokens;
       usuarios         heap r       postgres    false    7            �           0    0    COLUMN refresh_tokens.id    COMMENT     [   COMMENT ON COLUMN usuarios.refresh_tokens.id IS 'Clave primaria de la tabla RefreshToken';
          usuarios               postgres    false    228            �           0    0    COLUMN refresh_tokens.grant_id    COMMENT     n   COMMENT ON COLUMN usuarios.refresh_tokens.grant_id IS 'Id de usuario al que se le asignó el token generado';
          usuarios               postgres    false    228            �           0    0    COLUMN refresh_tokens.iat    COMMENT     P   COMMENT ON COLUMN usuarios.refresh_tokens.iat IS 'Fecha de creación de token';
          usuarios               postgres    false    228            �           0    0     COLUMN refresh_tokens.expires_at    COMMENT     V   COMMENT ON COLUMN usuarios.refresh_tokens.expires_at IS 'Fecha expiración de token';
          usuarios               postgres    false    228            �           0    0     COLUMN refresh_tokens.is_revoked    COMMENT     z   COMMENT ON COLUMN usuarios.refresh_tokens.is_revoked IS 'Estado de token, valor booleano para revocar el token generado';
          usuarios               postgres    false    228            �           0    0    COLUMN refresh_tokens.data    COMMENT     L   COMMENT ON COLUMN usuarios.refresh_tokens.data IS 'Información del token';
          usuarios               postgres    false    228            �            1259    47080    roles    TABLE     �  CREATE TABLE usuarios.roles (
    _estado character varying(30) NOT NULL,
    _transaccion character varying(30) NOT NULL,
    _usuario_creacion bigint NOT NULL,
    _fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    _usuario_modificacion bigint,
    _fecha_modificacion timestamp without time zone DEFAULT now(),
    id bigint NOT NULL,
    rol character varying(50) NOT NULL,
    nombre character varying(100) NOT NULL,
    descripcion character varying(255) NOT NULL,
    CONSTRAINT "CHK_7e56801a11afa1820594d681e8" CHECK (((_estado)::text = ANY ((ARRAY['ACTIVO'::character varying, 'INACTIVO'::character varying])::text[])))
);
    DROP TABLE usuarios.roles;
       usuarios         heap r       postgres    false    7            �           0    0    COLUMN roles._estado    COMMENT     C   COMMENT ON COLUMN usuarios.roles._estado IS 'Estado del registro';
          usuarios               postgres    false    223            �           0    0    COLUMN roles._transaccion    COMMENT     Q   COMMENT ON COLUMN usuarios.roles._transaccion IS 'Tipo de operación ejecutada';
          usuarios               postgres    false    223            �           0    0    COLUMN roles._usuario_creacion    COMMENT     ]   COMMENT ON COLUMN usuarios.roles._usuario_creacion IS 'Id de usuario que creó el registro';
          usuarios               postgres    false    223            �           0    0    COLUMN roles._fecha_creacion    COMMENT     J   COMMENT ON COLUMN usuarios.roles._fecha_creacion IS 'Fecha de creación';
          usuarios               postgres    false    223            �           0    0 "   COLUMN roles._usuario_modificacion    COMMENT     i   COMMENT ON COLUMN usuarios.roles._usuario_modificacion IS 'Id de usuario que realizo una modificación';
          usuarios               postgres    false    223            �           0    0     COLUMN roles._fecha_modificacion    COMMENT     f   COMMENT ON COLUMN usuarios.roles._fecha_modificacion IS 'Fecha en que se realizó una modificación';
          usuarios               postgres    false    223            �           0    0    COLUMN roles.id    COMMENT     I   COMMENT ON COLUMN usuarios.roles.id IS 'Clave primaria de la tabla Rol';
          usuarios               postgres    false    223            �           0    0    COLUMN roles.rol    COMMENT     8   COMMENT ON COLUMN usuarios.roles.rol IS 'Rol definido';
          usuarios               postgres    false    223            �           0    0    COLUMN roles.nombre    COMMENT     <   COMMENT ON COLUMN usuarios.roles.nombre IS 'Nombre de rol';
          usuarios               postgres    false    223            �           0    0    COLUMN roles.descripcion    COMMENT     G   COMMENT ON COLUMN usuarios.roles.descripcion IS 'Descripción de rol';
          usuarios               postgres    false    223            �            1259    47079    roles_id_seq    SEQUENCE     w   CREATE SEQUENCE usuarios.roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE usuarios.roles_id_seq;
       usuarios               postgres    false    7    223            �           0    0    roles_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE usuarios.roles_id_seq OWNED BY usuarios.roles.id;
          usuarios               postgres    false    222            �            1259    47102    usuarios    TABLE     8  CREATE TABLE usuarios.usuarios (
    _estado character varying(30) NOT NULL,
    _transaccion character varying(30) NOT NULL,
    _usuario_creacion bigint NOT NULL,
    _fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    _usuario_modificacion bigint,
    _fecha_modificacion timestamp without time zone DEFAULT now(),
    id bigint NOT NULL,
    usuario character varying(50) NOT NULL,
    contrasena character varying(255) NOT NULL,
    ciudadania_digital boolean DEFAULT false NOT NULL,
    correo_electronico character varying,
    intentos integer DEFAULT 0 NOT NULL,
    codigo_desbloqueo character varying(100),
    codigo_recuperacion character varying(100),
    codigo_transaccion character varying(100),
    codigo_activacion character varying(100),
    fecha_bloqueo timestamp without time zone,
    id_persona bigint NOT NULL,
    CONSTRAINT "CHK_b86f9009275cfc1b237eba3c47" CHECK (((_estado)::text = ANY ((ARRAY['ACTIVO'::character varying, 'INACTIVO'::character varying, 'CREADO'::character varying, 'PENDIENTE'::character varying])::text[])))
);
    DROP TABLE usuarios.usuarios;
       usuarios         heap r       postgres    false    7            �           0    0    COLUMN usuarios._estado    COMMENT     F   COMMENT ON COLUMN usuarios.usuarios._estado IS 'Estado del registro';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios._transaccion    COMMENT     T   COMMENT ON COLUMN usuarios.usuarios._transaccion IS 'Tipo de operación ejecutada';
          usuarios               postgres    false    227            �           0    0 !   COLUMN usuarios._usuario_creacion    COMMENT     `   COMMENT ON COLUMN usuarios.usuarios._usuario_creacion IS 'Id de usuario que creó el registro';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios._fecha_creacion    COMMENT     M   COMMENT ON COLUMN usuarios.usuarios._fecha_creacion IS 'Fecha de creación';
          usuarios               postgres    false    227            �           0    0 %   COLUMN usuarios._usuario_modificacion    COMMENT     l   COMMENT ON COLUMN usuarios.usuarios._usuario_modificacion IS 'Id de usuario que realizo una modificación';
          usuarios               postgres    false    227            �           0    0 #   COLUMN usuarios._fecha_modificacion    COMMENT     i   COMMENT ON COLUMN usuarios.usuarios._fecha_modificacion IS 'Fecha en que se realizó una modificación';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios.id    COMMENT     P   COMMENT ON COLUMN usuarios.usuarios.id IS 'Clave primaria de la tabla Usuario';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios.usuario    COMMENT     d   COMMENT ON COLUMN usuarios.usuarios.usuario IS 'nombre de usuario, usualmente carnet de identidad';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios.contrasena    COMMENT     M   COMMENT ON COLUMN usuarios.usuarios.contrasena IS 'contraseña del usuario';
          usuarios               postgres    false    227            �           0    0 "   COLUMN usuarios.ciudadania_digital    COMMENT     {   COMMENT ON COLUMN usuarios.usuarios.ciudadania_digital IS 'índica si el usuario tiene habilitada la ciudadanía digital';
          usuarios               postgres    false    227            �           0    0 "   COLUMN usuarios.correo_electronico    COMMENT     ]   COMMENT ON COLUMN usuarios.usuarios.correo_electronico IS 'correo electrónico del usuario';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios.intentos    COMMENT     e   COMMENT ON COLUMN usuarios.usuarios.intentos IS 'número de intentos de inicio de sesión fallidos';
          usuarios               postgres    false    227            �           0    0 !   COLUMN usuarios.codigo_desbloqueo    COMMENT     j   COMMENT ON COLUMN usuarios.usuarios.codigo_desbloqueo IS 'código de desbloqueo de la cuenta de usuario';
          usuarios               postgres    false    227            �           0    0 #   COLUMN usuarios.codigo_recuperacion    COMMENT     o   COMMENT ON COLUMN usuarios.usuarios.codigo_recuperacion IS 'código de recuperación de la cuenta de usuario';
          usuarios               postgres    false    227            �           0    0 "   COLUMN usuarios.codigo_transaccion    COMMENT     m   COMMENT ON COLUMN usuarios.usuarios.codigo_transaccion IS 'código de transacción de la cuenta de usuario';
          usuarios               postgres    false    227            �           0    0 !   COLUMN usuarios.codigo_activacion    COMMENT     k   COMMENT ON COLUMN usuarios.usuarios.codigo_activacion IS 'código de activación de la cuenta de usuario';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios.fecha_bloqueo    COMMENT     a   COMMENT ON COLUMN usuarios.usuarios.fecha_bloqueo IS 'fecha de bloqueo de la cuenta de usuario';
          usuarios               postgres    false    227            �           0    0    COLUMN usuarios.id_persona    COMMENT     h   COMMENT ON COLUMN usuarios.usuarios.id_persona IS 'clave foránea que referencia la tabla de Personas';
          usuarios               postgres    false    227            �            1259    47101    usuarios_id_seq    SEQUENCE     z   CREATE SEQUENCE usuarios.usuarios_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE usuarios.usuarios_id_seq;
       usuarios               postgres    false    7    227            �           0    0    usuarios_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE usuarios.usuarios_id_seq OWNED BY usuarios.usuarios.id;
          usuarios               postgres    false    226            �            1259    47092    usuarios_roles    TABLE     M  CREATE TABLE usuarios.usuarios_roles (
    _estado character varying(30) NOT NULL,
    _transaccion character varying(30) NOT NULL,
    _usuario_creacion bigint NOT NULL,
    _fecha_creacion timestamp without time zone DEFAULT now() NOT NULL,
    _usuario_modificacion bigint,
    _fecha_modificacion timestamp without time zone DEFAULT now(),
    id bigint NOT NULL,
    id_rol bigint NOT NULL,
    id_usuario bigint NOT NULL,
    CONSTRAINT "CHK_1d395c40701d7e78396c3fb6f1" CHECK (((_estado)::text = ANY ((ARRAY['ACTIVO'::character varying, 'INACTIVO'::character varying])::text[])))
);
 $   DROP TABLE usuarios.usuarios_roles;
       usuarios         heap r       postgres    false    7            �           0    0    COLUMN usuarios_roles._estado    COMMENT     L   COMMENT ON COLUMN usuarios.usuarios_roles._estado IS 'Estado del registro';
          usuarios               postgres    false    225            �           0    0 "   COLUMN usuarios_roles._transaccion    COMMENT     Z   COMMENT ON COLUMN usuarios.usuarios_roles._transaccion IS 'Tipo de operación ejecutada';
          usuarios               postgres    false    225            �           0    0 '   COLUMN usuarios_roles._usuario_creacion    COMMENT     f   COMMENT ON COLUMN usuarios.usuarios_roles._usuario_creacion IS 'Id de usuario que creó el registro';
          usuarios               postgres    false    225            �           0    0 %   COLUMN usuarios_roles._fecha_creacion    COMMENT     S   COMMENT ON COLUMN usuarios.usuarios_roles._fecha_creacion IS 'Fecha de creación';
          usuarios               postgres    false    225            �           0    0 +   COLUMN usuarios_roles._usuario_modificacion    COMMENT     r   COMMENT ON COLUMN usuarios.usuarios_roles._usuario_modificacion IS 'Id de usuario que realizo una modificación';
          usuarios               postgres    false    225            �           0    0 )   COLUMN usuarios_roles._fecha_modificacion    COMMENT     o   COMMENT ON COLUMN usuarios.usuarios_roles._fecha_modificacion IS 'Fecha en que se realizó una modificación';
          usuarios               postgres    false    225            �           0    0    COLUMN usuarios_roles.id    COMMENT     _   COMMENT ON COLUMN usuarios.usuarios_roles.id IS 'Clave primaria de la tabla de UsuariosRoles';
          usuarios               postgres    false    225            �           0    0    COLUMN usuarios_roles.id_rol    COMMENT     g   COMMENT ON COLUMN usuarios.usuarios_roles.id_rol IS 'Clave foránea que referencia la tabla de roles';
          usuarios               postgres    false    225            �           0    0     COLUMN usuarios_roles.id_usuario    COMMENT     k   COMMENT ON COLUMN usuarios.usuarios_roles.id_usuario IS 'Clave foránea que referencia la tabla usuarios';
          usuarios               postgres    false    225            �            1259    47091    usuarios_roles_id_seq    SEQUENCE     �   CREATE SEQUENCE usuarios.usuarios_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE usuarios.usuarios_roles_id_seq;
       usuarios               postgres    false    7    225            �           0    0    usuarios_roles_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE usuarios.usuarios_roles_id_seq OWNED BY usuarios.usuarios_roles.id;
          usuarios               postgres    false    224            �           2604    47151    parametros id    DEFAULT     z   ALTER TABLE ONLY parametricas.parametros ALTER COLUMN id SET DEFAULT nextval('parametricas.parametros_id_seq'::regclass);
 B   ALTER TABLE parametricas.parametros ALTER COLUMN id DROP DEFAULT;
       parametricas               postgres    false    232    233    233            ~           2604    47057    migrations id    DEFAULT     r   ALTER TABLE ONLY proyecto.migrations ALTER COLUMN id SET DEFAULT nextval('proyecto.migrations_id_seq'::regclass);
 >   ALTER TABLE proyecto.migrations ALTER COLUMN id DROP DEFAULT;
       proyecto               postgres    false    219    218    219            �           2604    47132    casbin_rule id    DEFAULT     t   ALTER TABLE ONLY usuarios.casbin_rule ALTER COLUMN id SET DEFAULT nextval('usuarios.casbin_rule_id_seq'::regclass);
 ?   ALTER TABLE usuarios.casbin_rule ALTER COLUMN id DROP DEFAULT;
       usuarios               postgres    false    230    229    230            �           2604    47163 
   modulos id    DEFAULT     l   ALTER TABLE ONLY usuarios.modulos ALTER COLUMN id SET DEFAULT nextval('usuarios.modulos_id_seq'::regclass);
 ;   ALTER TABLE usuarios.modulos ALTER COLUMN id DROP DEFAULT;
       usuarios               postgres    false    234    235    235            �           2604    47068    personas id    DEFAULT     n   ALTER TABLE ONLY usuarios.personas ALTER COLUMN id SET DEFAULT nextval('usuarios.personas_id_seq'::regclass);
 <   ALTER TABLE usuarios.personas ALTER COLUMN id DROP DEFAULT;
       usuarios               postgres    false    221    220    221            �           2604    47085    roles id    DEFAULT     h   ALTER TABLE ONLY usuarios.roles ALTER COLUMN id SET DEFAULT nextval('usuarios.roles_id_seq'::regclass);
 9   ALTER TABLE usuarios.roles ALTER COLUMN id DROP DEFAULT;
       usuarios               postgres    false    222    223    223            �           2604    47107    usuarios id    DEFAULT     n   ALTER TABLE ONLY usuarios.usuarios ALTER COLUMN id SET DEFAULT nextval('usuarios.usuarios_id_seq'::regclass);
 <   ALTER TABLE usuarios.usuarios ALTER COLUMN id DROP DEFAULT;
       usuarios               postgres    false    227    226    227            �           2604    47097    usuarios_roles id    DEFAULT     z   ALTER TABLE ONLY usuarios.usuarios_roles ALTER COLUMN id SET DEFAULT nextval('usuarios.usuarios_roles_id_seq'::regclass);
 B   ALTER TABLE usuarios.usuarios_roles ALTER COLUMN id DROP DEFAULT;
       usuarios               postgres    false    225    224    225            b          0    47146 
   parametros 
   TABLE DATA                 parametricas               postgres    false    233   ��       T          0    47054 
   migrations 
   TABLE DATA                 proyecto               postgres    false    219   '�       `          0    47137    session 
   TABLE DATA                 proyecto               postgres    false    231   �       _          0    47129    casbin_rule 
   TABLE DATA                 usuarios               postgres    false    230   6�       d          0    47158    modulos 
   TABLE DATA                 usuarios               postgres    false    235   ��       V          0    47063    personas 
   TABLE DATA                 usuarios               postgres    false    221   0�       ]          0    47121    refresh_tokens 
   TABLE DATA                 usuarios               postgres    false    228   +�       X          0    47080    roles 
   TABLE DATA                 usuarios               postgres    false    223   E�       \          0    47102    usuarios 
   TABLE DATA                 usuarios               postgres    false    227   h�       Z          0    47092    usuarios_roles 
   TABLE DATA                 usuarios               postgres    false    225   �       �           0    0    parametros_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('parametricas.parametros_id_seq', 13, true);
          parametricas               postgres    false    232            �           0    0    migrations_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('proyecto.migrations_id_seq', 7, true);
          proyecto               postgres    false    218            �           0    0    casbin_rule_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('usuarios.casbin_rule_id_seq', 42, true);
          usuarios               postgres    false    229            �           0    0    modulos_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('usuarios.modulos_id_seq', 9, true);
          usuarios               postgres    false    234            �           0    0    personas_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('usuarios.personas_id_seq', 3, true);
          usuarios               postgres    false    220            �           0    0    roles_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('usuarios.roles_id_seq', 3, true);
          usuarios               postgres    false    222            �           0    0    usuarios_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('usuarios.usuarios_id_seq', 3, true);
          usuarios               postgres    false    226            �           0    0    usuarios_roles_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('usuarios.usuarios_roles_id_seq', 4, true);
          usuarios               postgres    false    224            �           2606    47154 )   parametros PK_c01b42f38ccdc41bdce9cd9fa33 
   CONSTRAINT     o   ALTER TABLE ONLY parametricas.parametros
    ADD CONSTRAINT "PK_c01b42f38ccdc41bdce9cd9fa33" PRIMARY KEY (id);
 [   ALTER TABLE ONLY parametricas.parametros DROP CONSTRAINT "PK_c01b42f38ccdc41bdce9cd9fa33";
       parametricas                 postgres    false    233            �           2606    47156 )   parametros UQ_fd98c9e2a32e7abf2c1f8f9ec60 
   CONSTRAINT     n   ALTER TABLE ONLY parametricas.parametros
    ADD CONSTRAINT "UQ_fd98c9e2a32e7abf2c1f8f9ec60" UNIQUE (codigo);
 [   ALTER TABLE ONLY parametricas.parametros DROP CONSTRAINT "UQ_fd98c9e2a32e7abf2c1f8f9ec60";
       parametricas                 postgres    false    233            �           2606    47061 )   migrations PK_8c82d7f526340ab734260ea46be 
   CONSTRAINT     k   ALTER TABLE ONLY proyecto.migrations
    ADD CONSTRAINT "PK_8c82d7f526340ab734260ea46be" PRIMARY KEY (id);
 W   ALTER TABLE ONLY proyecto.migrations DROP CONSTRAINT "PK_8c82d7f526340ab734260ea46be";
       proyecto                 postgres    false    219            �           2606    47143 &   session PK_f55da76ac1c3ac420f444d2ff11 
   CONSTRAINT     h   ALTER TABLE ONLY proyecto.session
    ADD CONSTRAINT "PK_f55da76ac1c3ac420f444d2ff11" PRIMARY KEY (id);
 T   ALTER TABLE ONLY proyecto.session DROP CONSTRAINT "PK_f55da76ac1c3ac420f444d2ff11";
       proyecto                 postgres    false    231            �           2606    47100 -   usuarios_roles PK_28de221731be7761ba1b165df08 
   CONSTRAINT     o   ALTER TABLE ONLY usuarios.usuarios_roles
    ADD CONSTRAINT "PK_28de221731be7761ba1b165df08" PRIMARY KEY (id);
 [   ALTER TABLE ONLY usuarios.usuarios_roles DROP CONSTRAINT "PK_28de221731be7761ba1b165df08";
       usuarios                 postgres    false    225            �           2606    47076 '   personas PK_714aa5d028f8f3e6645e971cecd 
   CONSTRAINT     i   ALTER TABLE ONLY usuarios.personas
    ADD CONSTRAINT "PK_714aa5d028f8f3e6645e971cecd" PRIMARY KEY (id);
 U   ALTER TABLE ONLY usuarios.personas DROP CONSTRAINT "PK_714aa5d028f8f3e6645e971cecd";
       usuarios                 postgres    false    221            �           2606    47127 -   refresh_tokens PK_7d8bee0204106019488c4c50ffa 
   CONSTRAINT     o   ALTER TABLE ONLY usuarios.refresh_tokens
    ADD CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY (id);
 [   ALTER TABLE ONLY usuarios.refresh_tokens DROP CONSTRAINT "PK_7d8bee0204106019488c4c50ffa";
       usuarios                 postgres    false    228            �           2606    47168 &   modulos PK_ba8d97b7acc232a928b1d686c5f 
   CONSTRAINT     h   ALTER TABLE ONLY usuarios.modulos
    ADD CONSTRAINT "PK_ba8d97b7acc232a928b1d686c5f" PRIMARY KEY (id);
 T   ALTER TABLE ONLY usuarios.modulos DROP CONSTRAINT "PK_ba8d97b7acc232a928b1d686c5f";
       usuarios                 postgres    false    235            �           2606    47088 $   roles PK_c1433d71a4838793a49dcad46ab 
   CONSTRAINT     f   ALTER TABLE ONLY usuarios.roles
    ADD CONSTRAINT "PK_c1433d71a4838793a49dcad46ab" PRIMARY KEY (id);
 R   ALTER TABLE ONLY usuarios.roles DROP CONSTRAINT "PK_c1433d71a4838793a49dcad46ab";
       usuarios                 postgres    false    223            �           2606    47114 '   usuarios PK_d7281c63c176e152e4c531594a8 
   CONSTRAINT     i   ALTER TABLE ONLY usuarios.usuarios
    ADD CONSTRAINT "PK_d7281c63c176e152e4c531594a8" PRIMARY KEY (id);
 U   ALTER TABLE ONLY usuarios.usuarios DROP CONSTRAINT "PK_d7281c63c176e152e4c531594a8";
       usuarios                 postgres    false    227            �           2606    47136 *   casbin_rule PK_e147354d31e2748a3a5da5e3060 
   CONSTRAINT     l   ALTER TABLE ONLY usuarios.casbin_rule
    ADD CONSTRAINT "PK_e147354d31e2748a3a5da5e3060" PRIMARY KEY (id);
 X   ALTER TABLE ONLY usuarios.casbin_rule DROP CONSTRAINT "PK_e147354d31e2748a3a5da5e3060";
       usuarios                 postgres    false    230            �           2606    47116 '   usuarios UQ_0790a401b9d234fa921e9aa1777 
   CONSTRAINT     i   ALTER TABLE ONLY usuarios.usuarios
    ADD CONSTRAINT "UQ_0790a401b9d234fa921e9aa1777" UNIQUE (usuario);
 U   ALTER TABLE ONLY usuarios.usuarios DROP CONSTRAINT "UQ_0790a401b9d234fa921e9aa1777";
       usuarios                 postgres    false    227            �           2606    47078 '   personas UQ_13d89692f1434af629621487993 
   CONSTRAINT     p   ALTER TABLE ONLY usuarios.personas
    ADD CONSTRAINT "UQ_13d89692f1434af629621487993" UNIQUE (uuid_ciudadano);
 U   ALTER TABLE ONLY usuarios.personas DROP CONSTRAINT "UQ_13d89692f1434af629621487993";
       usuarios                 postgres    false    221            �           2606    47170 &   modulos UQ_90425c1640c0d15e56835cb0dc6 
   CONSTRAINT     d   ALTER TABLE ONLY usuarios.modulos
    ADD CONSTRAINT "UQ_90425c1640c0d15e56835cb0dc6" UNIQUE (url);
 T   ALTER TABLE ONLY usuarios.modulos DROP CONSTRAINT "UQ_90425c1640c0d15e56835cb0dc6";
       usuarios                 postgres    false    235            �           2606    47090 $   roles UQ_e9355d00b489aef35a3dbb5ea79 
   CONSTRAINT     b   ALTER TABLE ONLY usuarios.roles
    ADD CONSTRAINT "UQ_e9355d00b489aef35a3dbb5ea79" UNIQUE (rol);
 R   ALTER TABLE ONLY usuarios.roles DROP CONSTRAINT "UQ_e9355d00b489aef35a3dbb5ea79";
       usuarios                 postgres    false    223            �           1259    47144    IDX_28c5d1d16da7908c97c9bc2f74    INDEX     ]   CREATE INDEX "IDX_28c5d1d16da7908c97c9bc2f74" ON proyecto.session USING btree ("expiredAt");
 6   DROP INDEX proyecto."IDX_28c5d1d16da7908c97c9bc2f74";
       proyecto                 postgres    false    231            �           1259    47118    IDX_36cfdee58d872216c8b3459f28    INDEX     f   CREATE INDEX "IDX_36cfdee58d872216c8b3459f28" ON usuarios.usuarios USING btree (codigo_recuperacion);
 6   DROP INDEX usuarios."IDX_36cfdee58d872216c8b3459f28";
       usuarios                 postgres    false    227            �           1259    47119    IDX_3b6f33f6db6db2d4e658ecd4d5    INDEX     e   CREATE INDEX "IDX_3b6f33f6db6db2d4e658ecd4d5" ON usuarios.usuarios USING btree (codigo_transaccion);
 6   DROP INDEX usuarios."IDX_3b6f33f6db6db2d4e658ecd4d5";
       usuarios                 postgres    false    227            �           1259    47117    IDX_456af1be360cf169e437da4f57    INDEX     d   CREATE INDEX "IDX_456af1be360cf169e437da4f57" ON usuarios.usuarios USING btree (codigo_desbloqueo);
 6   DROP INDEX usuarios."IDX_456af1be360cf169e437da4f57";
       usuarios                 postgres    false    227            �           1259    47120    IDX_bf266c21a9837e1a2d88646d09    INDEX     d   CREATE INDEX "IDX_bf266c21a9837e1a2d88646d09" ON usuarios.usuarios USING btree (codigo_activacion);
 6   DROP INDEX usuarios."IDX_bf266c21a9837e1a2d88646d09";
       usuarios                 postgres    false    227            �           2606    47181 '   usuarios FK_5b29c4b5cc11b9c67c8b70c9cb2    FK CONSTRAINT     �   ALTER TABLE ONLY usuarios.usuarios
    ADD CONSTRAINT "FK_5b29c4b5cc11b9c67c8b70c9cb2" FOREIGN KEY (id_persona) REFERENCES usuarios.personas(id);
 U   ALTER TABLE ONLY usuarios.usuarios DROP CONSTRAINT "FK_5b29c4b5cc11b9c67c8b70c9cb2";
       usuarios               postgres    false    221    227    4768            �           2606    47186 &   modulos FK_68ad50fa332064a72e31fcdf87a    FK CONSTRAINT     �   ALTER TABLE ONLY usuarios.modulos
    ADD CONSTRAINT "FK_68ad50fa332064a72e31fcdf87a" FOREIGN KEY (id_modulo) REFERENCES usuarios.modulos(id);
 T   ALTER TABLE ONLY usuarios.modulos DROP CONSTRAINT "FK_68ad50fa332064a72e31fcdf87a";
       usuarios               postgres    false    235    235    4797            �           2606    47171 -   usuarios_roles FK_c658b8c0773fc6a78fcd295878d    FK CONSTRAINT     �   ALTER TABLE ONLY usuarios.usuarios_roles
    ADD CONSTRAINT "FK_c658b8c0773fc6a78fcd295878d" FOREIGN KEY (id_rol) REFERENCES usuarios.roles(id);
 [   ALTER TABLE ONLY usuarios.usuarios_roles DROP CONSTRAINT "FK_c658b8c0773fc6a78fcd295878d";
       usuarios               postgres    false    4772    223    225            �           2606    47176 -   usuarios_roles FK_fff4c9f548a476cc170128314dc    FK CONSTRAINT     �   ALTER TABLE ONLY usuarios.usuarios_roles
    ADD CONSTRAINT "FK_fff4c9f548a476cc170128314dc" FOREIGN KEY (id_usuario) REFERENCES usuarios.usuarios(id);
 [   ALTER TABLE ONLY usuarios.usuarios_roles DROP CONSTRAINT "FK_fff4c9f548a476cc170128314dc";
       usuarios               postgres    false    4782    225    227            b   u  x^͕�n� ��}
�%�T��Z��IcK�'����d���؋��-j�e��>�}�C��ي�x�St�xWu�݈c���h$�ѝP�S�y9cQ�=&>a���Lf#ҟL��X�/�$�c�#Lc8�~}��N ��V���J!A�Qg5���Ͻ��M����XRu%�WU��dw�:�p�,�!��b����h�Zr�����ڼڗu�jN��/�s��J5�	�"�	ұ%- �t��V�4�E��A;��7�b;�T_�+�SKkڝT;ա�X�\�}jhC� ��mL������D��g+^In�����W��ӗ�f/����Ӭ!6����m����TS\M%]��R\��7�H      T   �   x^���J�0�{�"�*,�I�L�'�=d���=j�@�H�|{��-�f�f>f&��|�.�=]�ɷw?�Gtw���&Z7����z<�8@�Q	&���@�v�q�շ�U�O�%O 倚&o�������d�+�i����<�▖��**��H�wC���.�/�$M+��_w���rU�)��ak;���G����Cv%8f\1�4(���/ƛ��ޭ�V��U�n��x      `   
   x^��          _   �  x^��͎�0��y
v�VU)0�_��Hi2
d�#xZ����YT<|N��z6$!����ߵ�7��n���#�x��d�J�q��^`���7����������&�S�����[��������������Ѭ�Y��o�������¿Ԑ�
���_ng� �:�r�P�KF��A z�=���@��RW��Qe$�	)	/���w�8�M���t��I�� \��35�Y�K/����7d�Y�z���7M[�4��%�xL!]�|�9�TR����:� �Mf	�E91QURF����̜ ��w� �W������?�rxDџ�I�ec#H�%89)�yC���A�	�+i�z�/��n�+&�J��T�J�z	�^�d/�Ӟ�����}xpf���@q����,i|�i�b��'��i�5�>�r�g��o_�����UЮ�v�|���*#�,�I�c�uU���B>�pV"3"U�b��$�{���Qt�4���Й;ߏ���R��(�:I��D�:P%/8{&�iع8
�N��p;eNhWV�q��G���ܦ
vJ^t7�@���7���_�ʩ�ޡ1�6<p��ԧG?�RR������,���oF@i������P���ĺ茻X���=      d   ?  x^͕�n�@��<��Z�I�H�)JQe��*|\�f=�#ٻ�>L �</�Yۘ5E�'��~x�7��������M�5*s��0��a˻�b<c��w��`����ڳ��ی�.�~��_t]����?����M�7���b2�`�=�F)0�=�*uG��O��7�?�B0Bc*PY�7!p�&Y���[]���Vp�}
*�H�,��a���J���x�P(�l(vң�D�D�q{B�� 1䌶3�5�ͫ�PpCKbfh1$���=-��M7�5��.a��cg98�i(�B���@��NxY6��(���h�;V�f�]xD��ý�k�rJ��UA���u)	���v�8��V1��{&��ST���8��mA���NM$\�V\���|��i���¸>�0V\o�%@W-�UIz�L#�H��F�8P��,	��pv ����[��8���zӉ��4+���~�������/�N���~o^���f_�X�Rw�����*7�]-Ps�'�h�Zd���x[T̾�[���[B�B$�rL��8��d�r	��@���m�z���G8�Z�$���      V   �   x^�ѱn� ��O��V*���t�iD��&R�eȐ��b���]˩ZU��8~����1�kɵ�.�s�x;^���';�Qr��3�6 yк���2I9(����d�L�.Z�K$��R/�񾭽�D��84ڏ[��6��J.�60��v�?m|���O��C�8�+t�·[�.�M��¸�ڼ��2A�����+f�V�8rf�Wh��$�J���*��'W��q8��      ]   
   x^��          X     x^͒�N�0��>�m�V����LV��RH�8�n�k9)��W�7b`��b8eC�a��>���D!��QT[��+K�ͬ�����u&�&�J��D2�R�<h��4^N�X�f����V�q�����_ZF�>�BȪ���yۓ&7X�;&JtG��z�Z�N��@�O�����%<�F���ՁثYt�0���U�)�沺���hj��g�V��zP.`��n��p� ���cOM(��$�Բ楸���_3J�[:Q��x?PGo
~d2�)��       \     x^��AO�0��>E$h"]��m%���3�MP�?�E����.�?��?/�'U"�I�F�k����[|(s��HЙ�z��"���~��8a������f�_-�������C�d�Ʈ�c�k��o��Y�~��\�������������7�o�k!�f�M0�ɷm�k�ǲ�
�8�S�z��]^mqQ��9����ϗ�_M�	e໌�
OI��+D9s���
���l�o&��g�X[�L&r���      Z   �   x^��v
Q���W(-.M,��/փ1��sR��}B]�4��C<���uԃ]]]��C ����T��L��H��������H�����(���C@	�Ҵ��p���b4(�bt�`q�	�-��p�� ��1     