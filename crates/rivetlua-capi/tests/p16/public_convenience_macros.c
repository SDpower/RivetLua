#if defined(RV_PROFILE_LUA54) && !defined(RV_PROFILE_LUA55)
#include <rivetlua/lua54/lua.h>
#include <rivetlua/lua54/lauxlib.h>
#elif defined(RV_PROFILE_LUA55) && !defined(RV_PROFILE_LUA54)
#include <rivetlua/lua55/lua.h>
#include <rivetlua/lua55/lauxlib.h>
#else
#error "請且只定義 RV_PROFILE_LUA54 或 RV_PROFILE_LUA55"
#endif

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            result = __LINE__; \
            goto cleanup; \
        } \
    } while (0)

int main(void) {
    lua_State *state;
    void *userdata;
    int result = 1;

    state = luaL_newstate();
    if (state == NULL) {
        return result;
    }

    CHECK(lua_gettop(state) == 0);

    lua_pushinteger(state, 11);
    lua_pushinteger(state, 22);
    lua_pushinteger(state, 33);
    CHECK(lua_gettop(state) == 3);

    lua_insert(state, 1);
    CHECK(lua_gettop(state) == 3);
    CHECK(lua_isinteger(state, 1) && lua_tointegerx(state, 1, NULL) == 33);
    CHECK(lua_isinteger(state, 2) && lua_tointegerx(state, 2, NULL) == 11);
    CHECK(lua_isinteger(state, 3) && lua_tointegerx(state, 3, NULL) == 22);

    lua_remove(state, 2);
    CHECK(lua_gettop(state) == 2);
    CHECK(lua_isinteger(state, 1) && lua_tointegerx(state, 1, NULL) == 33);
    CHECK(lua_isinteger(state, 2) && lua_tointegerx(state, 2, NULL) == 22);

    lua_pushinteger(state, 44);
    lua_replace(state, 1);
    CHECK(lua_gettop(state) == 2);
    CHECK(lua_isinteger(state, 1) && lua_tointegerx(state, 1, NULL) == 44);
    CHECK(lua_isinteger(state, 2) && lua_tointegerx(state, 2, NULL) == 22);

    lua_pushinteger(state, 55);
    CHECK(lua_gettop(state) == 3);
    CHECK(lua_isinteger(state, 3) && lua_tointegerx(state, 3, NULL) == 55);
    lua_pop(state, 1);
    CHECK(lua_gettop(state) == 2);
    CHECK(lua_isinteger(state, 1) && lua_tointegerx(state, 1, NULL) == 44);
    CHECK(lua_isinteger(state, 2) && lua_tointegerx(state, 2, NULL) == 22);

    userdata = lua_newuserdata(state, sizeof(int));
    CHECK(userdata != NULL);
    CHECK(lua_gettop(state) == 3);
    CHECK(lua_type(state, -1) == LUA_TUSERDATA);
    CHECK(lua_rawlen(state, -1) == sizeof(int));

    lua_pushinteger(state, 91);
    CHECK(lua_setiuservalue(state, -2, 1) == 1);
    CHECK(lua_gettop(state) == 3);
    CHECK(lua_getiuservalue(state, -1, 1) == LUA_TNUMBER);
    CHECK(lua_gettop(state) == 4);
    CHECK(lua_isinteger(state, -1));
    CHECK(lua_tointegerx(state, -1, NULL) == 91);
    lua_pop(state, 1);
    CHECK(lua_gettop(state) == 3);

    lua_pushinteger(state, 92);
    CHECK(lua_gettop(state) == 4);
    lua_setuservalue(state, -2);
    CHECK(lua_gettop(state) == 3);
    CHECK(lua_getuservalue(state, -1) == LUA_TNUMBER);
    CHECK(lua_gettop(state) == 4);
    CHECK(lua_isinteger(state, -1));
    CHECK(lua_tointegerx(state, -1, NULL) == 92);
    lua_pop(state, 1);
    CHECK(lua_gettop(state) == 3);

    result = 0;
cleanup:
    lua_close(state);
    return result;
}
