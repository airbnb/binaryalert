rule ransomware_windows_petya_variant_bitcoin
{
    meta:
        description = "Petya Ransomware new variant June 2017 using ETERNALBLUE: Bitcoin"
        reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
        author = "@fusionrace"
        md5 = "71b6a493388e7d0b40c83ce903bc6b04"
    strings:
        //Bitcoin address
        $s1 = "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB" fullword wide
    condition:
        $s1
}
