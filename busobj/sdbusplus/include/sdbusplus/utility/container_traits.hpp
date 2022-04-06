#pragma once

namespace sdbusplus
{
namespace utility
{

/** has_const_iterator - Determine if type has const iterator
 *
 *  @tparam T - Type to be tested.
 *
 *  @value A value as to whether or not the type supports iteration
 */
template <typename T>
struct has_const_iterator
{
  private:
    typedef char yes;
    typedef struct
    {
        char array[2];
    } no;

    template <typename C>
    static constexpr yes test(typename C::const_iterator*);
    template <typename C>
    static constexpr no test(...);

  public:
    static constexpr bool value = sizeof(test<T>(0)) == sizeof(yes);
};

template <typename T>
inline constexpr bool has_const_iterator_v = has_const_iterator<T>::value;

/** has_emplace_method - Determine if type has a method template named emplace
 *
 *  @tparam T - Type to be tested.
 *
 *  @value A value as to whether or not the type has an emplace method
 */
template <typename T>
struct has_emplace_method
{
  private:
    struct dummy
    {};

    template <typename C, typename P>
    static constexpr auto test(P* p)
        -> decltype(std::declval<C>().emplace(*p), std::true_type());

    template <typename, typename>
    static std::false_type test(...);

  public:
    static constexpr bool value =
        std::is_same_v<std::true_type, decltype(test<T, dummy>(nullptr))>;
};

template <typename T>
inline constexpr bool has_emplace_method_v = has_emplace_method<T>::value;

#ifdef WIN32
template <typename T, typename = void>
struct has_value_type : std::false_type
{};

template <typename T>
struct has_value_type<T, std::void_t<typename T::value_type>> : std::true_type
{};

template <class T>
constexpr bool has_value_type_v = has_value_type<T>::value;
#endif

/** has_emplace_method - Determine if type has a method template named
 * emplace_back
 *
 *  @tparam T - Type to be tested.
 *
 *  @value A value as to whether or not the type has an emplace_back method
 */
template <typename T>
struct has_emplace_back_method
{
  private:
    struct dummy
    {};

    template <typename C, typename P>
    static constexpr auto test(P* p)
        -> decltype(std::declval<C>().emplace_back(*p), std::true_type());

    template <typename, typename>
    static std::false_type test(...);

  public:
#ifdef WIN32
    static constexpr bool value = []() {
        if constexpr (has_value_type_v<T>)
            return std::is_same_v<std::true_type,
                                  decltype(test<T, T::value_type>(nullptr))>;
        else
            return std::is_same_v<std::true_type,
                                  decltype(test<T, dummy>(nullptr))>;
    }();
#else
    static constexpr bool value =
        std::is_same_v<std::true_type, decltype(test<T, dummy>(nullptr))>;
#endif
};

template <typename T>
inline constexpr bool has_emplace_back_method_v =
    has_emplace_back_method<T>::value;

} // namespace utility
} // namespace sdbusplus
