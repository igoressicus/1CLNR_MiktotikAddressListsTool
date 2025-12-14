#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import argparse
import ipaddress
import logging
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional
from collections import defaultdict
import socket

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class IPOptimizer:
    """Класс для оптимизации IP-адресов и подсетей"""
    
    @staticmethod
    def cidr_to_network(cidr: str) -> ipaddress.IPv4Network:
        """Преобразование CIDR в сетевой объект"""
        try:
            return ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as e:
            logger.warning(f"Неверный CIDR формат: {cidr}. Ошибка: {e}")
            raise
    
    @staticmethod
    def mask_to_prefix(mask: str) -> int:
        """Преобразование маски в префикс CIDR"""
        try:
            # Создаем объект IPv4Address из строки маски
            mask_addr = ipaddress.IPv4Address(mask)
            mask_int = int(mask_addr)
            
            # Подсчитываем количество единичных битов
            prefix_len = 0
            for i in range(32):
                if mask_int & (1 << (31 - i)):
                    prefix_len += 1
                else:
                    # Проверяем, что после нуля не идут единицы (невалидная маска)
                    if mask_int & ((1 << (31 - i)) - 1):
                        raise ValueError(f"Некорректная маска: {mask}")
            
            return prefix_len
            
        except ValueError as e:
            logger.warning(f"Ошибка преобразования маски {mask}: {e}")
            raise
    
    @staticmethod
    def mask_and_ip_to_cidr(ip: str, mask: str) -> str:
        """Преобразование IP и маски в CIDR запись"""
        try:
            prefix = IPOptimizer.mask_to_prefix(mask)
            return f"{ip}/{prefix}"
        except Exception as e:
            logger.warning(f"Ошибка преобразования IP {ip} с маской {mask} в CIDR: {e}")
            raise
    
    @staticmethod
    def remove_subnets(subnets: Set[ipaddress.IPv4Network]) -> Set[ipaddress.IPv4Network]:
        """Удаление подсетей, которые входят в другие подсети"""
        if not subnets:
            return set()
        
        # Сортируем по размеру префикса (от большего к меньшему)
        sorted_subnets = sorted(subnets, key=lambda x: x.prefixlen, reverse=True)
        result = set()
        
        for subnet in sorted_subnets:
            # Проверяем, не входит ли эта подсеть в уже добавленную
            is_subnet = False
            for existing in result:
                if existing.supernet_of(subnet):
                    is_subnet = True
                    logger.debug(f"Удаляем подсеть {subnet}, так как она входит в {existing}")
                    break
            
            if not is_subnet:
                result.add(subnet)
        
        return result
    
    @staticmethod
    def merge_adjacent_subnets(subnets: Set[ipaddress.IPv4Network]) -> Set[ipaddress.IPv4Network]:
        """Объединение соседних подсетей"""
        if not subnets:
            return set()
        
        # Сортируем подсети
        sorted_subnets = sorted(subnets, key=lambda x: (x.network_address, x.prefixlen))
        result = set()
        merged = True
        
        while merged:
            merged = False
            temp_list = sorted(sorted_subnets, key=lambda x: (x.network_address, x.prefixlen))
            sorted_subnets = []
            i = 0
            
            while i < len(temp_list):
                if i + 1 < len(temp_list):
                    net1 = temp_list[i]
                    net2 = temp_list[i + 1]
                    
                    # Проверяем, можно ли объединить подсети
                    if net1.prefixlen == net2.prefixlen and net1.prefixlen > 0:
                        # Проверяем, являются ли подсети соседними
                        if int(net1.network_address) + 2**(32 - net1.prefixlen) == int(net2.network_address):
                            # Объединяем в суперсеть
                            try:
                                supernet = ipaddress.IPv4Network(f"{net1.network_address}/{net1.prefixlen - 1}", strict=False)
                                sorted_subnets.append(supernet)
                                logger.debug(f"Объединяем {net1} и {net2} в {supernet}")
                                i += 2
                                merged = True
                                continue
                            except ValueError:
                                # Не удалось объединить, оставляем как есть
                                pass
                
                sorted_subnets.append(temp_list[i])
                i += 1
        
        return set(sorted_subnets)
    
    @staticmethod
    def optimize_subnets(subnets: Set[ipaddress.IPv4Network]) -> Set[ipaddress.IPv4Network]:
        """Полная оптимизация подсетей"""
        if not subnets:
            return set()
        
        # Удаляем подсети, входящие в другие
        optimized = IPOptimizer.remove_subnets(subnets)
        
        # Объединяем соседние подсети
        optimized = IPOptimizer.merge_adjacent_subnets(optimized)
        
        # Повторно удаляем подсети, которые могли стать подсетями после объединения
        optimized = IPOptimizer.remove_subnets(optimized)
        
        logger.info(f"Оптимизация: было {len(subnets)} подсетей, стало {len(optimized)}")
        return optimized

class DomainProcessor:
    """Класс для обработки доменных имен"""
    
    @staticmethod
    def clean_domain(domain: str) -> List[str]:
        """Очистка доменного имени от протоколов и преобразование в нужный формат"""
        domain = domain.strip()
        
        # Удаление протоколов
        for prefix in ['http://', 'https://', 'ftp://', 'ftps://', 'sftp://']:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        
        # Удаление портов
        domain = domain.split(':')[0]
        
        # Удаление пути
        domain = domain.split('/')[0]
        
        # Удаление параметров запроса
        domain = domain.split('?')[0]
        
        if not domain:
            return []
        
        result = [domain]
        
        # Добавляем www. версию, если ее нет
        if not domain.startswith('www.'):
            result.append(f'www.{domain}')
        
        return result
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Проверка валидности доменного имени"""
        if not domain:
            return False
        
        # Простая проверка
        if len(domain) > 253:
            return False
        
        # Проверка на наличие недопустимых символов
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            return False
        
        # Домен должен содержать точку
        if '.' not in domain:
            return False
        
        return True

class MikrotikFormatter:
    """Класс для форматирования команд Mikrotik"""
    
    @staticmethod
    def clean_command(command: str) -> str:
        """Очистка команды от лишних пробелов и символов"""
        # Удаляем лишние пробелы
        command = ' '.join(command.split())
        
        # Удаляем недопустимые символы (оставляем только буквы, цифры, точки, дефисы, =, /, :, @, _, -)
        command = re.sub(r'[^\w\s\.=/:@-]', '', command)
        
        return command.strip()
    
    @staticmethod
    def format_address_entry(address: str, list_name: str, comment: str = None) -> str:
        """Форматирование записи адреса"""
        # Приводим имя списка к нижнему регистру
        list_name_clean = re.sub(r'[^\w-]', '', list_name).lower()
        address_clean = address.strip()
        
        if comment:
            comment_clean = re.sub(r'[^\w\s-]', '', comment)
            cmd = f'add address={address_clean} comment={comment_clean} list={list_name_clean}'
        else:
            cmd = f'add address={address_clean} list={list_name_clean}'
        
        return MikrotikFormatter.clean_command(cmd)
    
    @staticmethod
    def format_mangle_entry(list_name: str, mark_name: str) -> str:
        """Форматирование записи mangle"""
        # Приводим имя списка к нижнему регистру
        list_name_clean = re.sub(r'[^\w-]', '', list_name).lower()
        mark_name_clean = re.sub(r'[^\w-]', '', mark_name)
        
        cmd = f'add action=mark-routing chain=prerouting dst-address-list={list_name_clean} new-routing-mark={mark_name_clean} passthrough=no'
        return MikrotikFormatter.clean_command(cmd)

class RouteFileParser:
    """Класс для парсинга BAT файлов с route add командами"""
    
    @staticmethod
    def parse_bat_file(file_path: Path) -> List[str]:
        """Парсинг BAT файла и извлечение IP-адресов"""
        ip_subnets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Ищем все route add команды (регистронезависимо)
            pattern = r'route\s+add\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)\s+'
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            logger.debug(f"Найдено {len(matches)} route add команд в файле {file_path.name}")
            
            for ip, mask in matches:
                try:
                    # Преобразуем IP и маску в CIDR
                    cidr = IPOptimizer.mask_and_ip_to_cidr(ip, mask)
                    ip_subnets.append(cidr)
                    logger.debug(f"Найден IP в BAT файле: {cidr} (из {ip} с маской {mask})")
                    
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Ошибка парсинга IP {ip} с маской {mask}: {e}")
        
        except Exception as e:
            logger.error(f"Ошибка чтения файла {file_path}: {e}")
        
        return ip_subnets

class ExistingListsParser:
    """Класс для парсинга существующих списков"""
    
    @staticmethod
    def parse_existing_file(file_path: Path) -> Dict[str, Set]:
        """Парсинг существующего файла со списками"""
        lists_dict = defaultdict(set)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    if not line or line.startswith('#') or line.startswith('/'):
                        continue
                    
                    # Ищем адреса в формате Mikrotik
                    match = re.search(r'add\s+address=([^\s]+)\s+.*list=([^\s]+)', line)
                    
                    if match:
                        address = match.group(1)
                        list_name = match.group(2).lower()  # Приводим к нижнему регистру
                        
                        # Извлекаем комментарий, если есть
                        comment_match = re.search(r'comment=([^\s]+)', line)
                        comment = comment_match.group(1) if comment_match else None
                        
                        # Пытаемся определить тип адреса
                        if '/' in address:
                            # Это IP-адрес с маской
                            try:
                                network = ipaddress.IPv4Network(address, strict=False)
                                # Сохраняем как кортеж (network, comment) для возможности сохранения комментариев
                                lists_dict[list_name].add((network, comment))
                                logger.debug(f"Найден IP в существующем файле: {address} для списка {list_name}")
                            except ValueError as e:
                                logger.warning(f"Неверный IP формат в строке {line_num}: {address}")
                        else:
                            # Это доменное имя, добавляем как строку
                            # Для доменов создаем отдельный ключ с суффиксом _domains
                            domain_key = f"{list_name}_domains"
                            lists_dict[domain_key].add((address, comment))
                            logger.debug(f"Найден домен в существующем файле: {address} для списка {list_name}")
        
        except Exception as e:
            logger.error(f"Ошибка парсинга существующего файла {file_path}: {e}")
        
        return dict(lists_dict)

class FolderScanner:
    """Класс для сканирования папок и обработки файлов"""
    
    def __init__(self, root_folder: Path):
        self.root_folder = Path(root_folder)
        self.ip_lists = defaultdict(set)  # Списки IP-адресов (с комментариями)
        self.domain_lists = defaultdict(set)  # Списки доменов (с комментариями)
    
    def scan(self):
        """Сканирование всех подпапок и файлов"""
        if not self.root_folder.exists():
            logger.error(f"Папка не существует: {self.root_folder}")
            return False
        
        logger.info(f"Начинаю сканирование папки: {self.root_folder}")
        
        for folder_path in self.root_folder.iterdir():
            if folder_path.is_dir():
                folder_name = folder_path.name.lower()  # Приводим к нижнему регистру
                logger.info(f"Обработка папки: {folder_name}")
                
                # Сканируем файлы в папке
                self._process_folder(folder_path, folder_name)
        
        return True
    
    def _process_folder(self, folder_path: Path, folder_name: str):
        """Обработка файлов в папке"""
        for file_path in folder_path.iterdir():
            if file_path.is_file():
                if file_path.suffix.lower() == '.bat':
                    self._process_bat_file(file_path, folder_name)
                elif file_path.name.lower().endswith('_domain'):  # Приводим к нижнему регистру
                    self._process_domain_file(file_path, folder_name)
    
    def _process_bat_file(self, file_path: Path, folder_name: str):
        """Обработка BAT файла"""
        logger.info(f"Обработка BAT файла: {file_path.name}")
        
        ip_subnets = RouteFileParser.parse_bat_file(file_path)
        
        for cidr in ip_subnets:
            try:
                network = IPOptimizer.cidr_to_network(cidr)
                # Добавляем без комментария для новых записей из BAT файлов
                self.ip_lists[folder_name].add((network, None))
                logger.debug(f"Добавлен IP: {cidr} в список {folder_name}")
            except ValueError as e:
                logger.warning(f"Пропускаем неверный CIDR: {cidr}. Ошибка: {e}")
    
    def _process_domain_file(self, file_path: Path, folder_name: str):
        """Обработка файла с доменами"""
        logger.info(f"Обработка доменного файла: {file_path.name}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    domain = line.strip()
                    if domain:
                        cleaned_domains = DomainProcessor.clean_domain(domain)
                        
                        for cleaned_domain in cleaned_domains:
                            if DomainProcessor.is_valid_domain(cleaned_domain):
                                # Добавляем без комментария для новых записей из domain файлов
                                self.domain_lists[folder_name].add((cleaned_domain, None))
                                logger.debug(f"Добавлен домен: {cleaned_domain} в список {folder_name}")
                            else:
                                logger.warning(f"Недопустимый домен в строке {line_num}: {domain}")
        
        except Exception as e:
            logger.error(f"Ошибка чтения доменного файла {file_path}: {e}")
    
    def get_optimized_lists(self) -> Tuple[Dict[str, Set[Tuple]], Dict[str, Set[Tuple]]]:
        """Получение оптимизированных списков"""
        optimized_ip_lists = {}
        
        # Оптимизируем IP-адреса
        for list_name, entries in self.ip_lists.items():
            # Извлекаем только подсети для оптимизации
            subnets = {entry[0] for entry in entries}
            optimized_subnets = IPOptimizer.optimize_subnets(subnets)
            
            # Создаем новый набор записей с сохранением комментариев
            optimized_entries = set()
            for subnet in optimized_subnets:
                # Находим соответствующий комментарий (если был)
                comment = None
                for entry_subnet, entry_comment in entries:
                    if entry_subnet == subnet and entry_comment:
                        comment = entry_comment
                        break
                optimized_entries.add((subnet, comment))
            
            optimized_ip_lists[list_name] = optimized_entries
        
        return optimized_ip_lists, self.domain_lists

class OutputGenerator:
    """Класс для генерации выходных файлов"""
    
    def __init__(self, output_path: Path, mark_name: str):
        self.output_path = output_path
        self.mark_name = mark_name
    
    def generate_files(self, 
                      ip_lists: Dict[str, Set[Tuple]], 
                      domain_lists: Dict[str, Set[Tuple]],
                      existing_lists: Dict[str, Set[Tuple]] = None):
        """Генерация всех выходных файлов"""
        
        # Объединяем со существующими списками
        if existing_lists:
            ip_lists, domain_lists = self._merge_with_existing(ip_lists, domain_lists, existing_lists)
        
        # Сортируем имена списков (уже в нижнем регистре)
        all_list_names = sorted(set(list(ip_lists.keys()) + list(domain_lists.keys())))
        
        # Генерируем файл со списками адресов
        self._generate_lists_file(all_list_names, ip_lists, domain_lists)
        
        # Генерируем файл mangle правил
        self._generate_mangle_file(all_list_names)
        
        logger.info(f"Файлы успешно сгенерированы в папке: {self.output_path}")
    
    def _merge_with_existing(self, 
                            ip_lists: Dict[str, Set[Tuple]], 
                            domain_lists: Dict[str, Set[Tuple]],
                            existing_lists: Dict[str, Set[Tuple]]) -> Tuple[Dict, Dict]:
        """Объединение с существующими списками"""
        
        for key, entries in existing_lists.items():
            if key.endswith('_domains'):
                # Это домены
                list_name = key[:-8]  # Убираем суффикс _domains (уже в нижнем регистре)
                
                # Объединяем домены
                existing_domains = set()
                for domain, comment in entries:
                    existing_domains.add((domain, comment))
                
                if list_name in domain_lists:
                    domain_lists[list_name].update(existing_domains)
                else:
                    domain_lists[list_name] = existing_domains
                
                logger.info(f"Добавлено {len(existing_domains)} доменов из существующего файла в список {list_name}")
            else:
                # Это IP-адреса (имена уже в нижнем регистре)
                existing_networks = set()
                for entry in entries:
                    if isinstance(entry, tuple) and len(entry) == 2:
                        network, comment = entry
                        if isinstance(network, str):
                            try:
                                network = ipaddress.IPv4Network(network, strict=False)
                                existing_networks.add((network, comment))
                            except ValueError:
                                logger.warning(f"Пропускаем неверный IP в существующем списке: {network}")
                        elif isinstance(network, ipaddress.IPv4Network):
                            existing_networks.add((network, comment))
                
                if existing_networks:
                    if key in ip_lists:
                        # Оптимизируем объединенный набор
                        all_networks = set()
                        all_comments = {}
                        
                        # Собираем все сети из текущего списка
                        for net, comment in ip_lists[key]:
                            all_networks.add(net)
                            if comment:
                                all_comments[net] = comment
                        
                        # Добавляем сети из существующего файла
                        for net, comment in existing_networks:
                            all_networks.add(net)
                            if comment:
                                all_comments[net] = comment
                        
                        # Оптимизируем
                        optimized_networks = IPOptimizer.optimize_subnets(all_networks)
                        
                        # Создаем новый набор с комментариями
                        new_entries = set()
                        for net in optimized_networks:
                            comment = all_comments.get(net)
                            new_entries.add((net, comment))
                        
                        ip_lists[key] = new_entries
                    else:
                        ip_lists[key] = existing_networks
                    
                    logger.info(f"Добавлено {len(existing_networks)} IP-адресов из существующего файла в список {key}")
        
        return ip_lists, domain_lists
    
    def _generate_lists_file(self, 
                            list_names: List[str], 
                            ip_lists: Dict[str, Set[Tuple]], 
                            domain_lists: Dict[str, Set[Tuple]]):
        """Генерация файла out.lists.rsc"""
        output_file = self.output_path / "out.lists.rsc"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # Заголовок файла
                f.write("/ip firewall address-list\n")
                
                # Записываем данные для каждого списка
                for list_name in list_names:
                    # IP-адреса
                    if list_name in ip_lists:
                        # Сортируем по IP и префиксу
                        sorted_entries = sorted(ip_lists[list_name], 
                                              key=lambda x: (x[0].network_address, x[0].prefixlen))
                        
                        for network, comment in sorted_entries:
                            entry = MikrotikFormatter.format_address_entry(str(network), list_name, comment)
                            f.write(f"{entry}\n")
                    
                    # Домены
                    if list_name in domain_lists:
                        # Сортируем по доменному имени
                        sorted_entries = sorted(domain_lists[list_name], key=lambda x: x[0])
                        
                        for domain, comment in sorted_entries:
                            entry = MikrotikFormatter.format_address_entry(domain, list_name, comment)
                            f.write(f"{entry}\n")
            
            logger.info(f"Файл списков создан: {output_file}")
            
        except Exception as e:
            logger.error(f"Ошибка создания файла списков: {e}")
    
    def _generate_mangle_file(self, list_names: List[str]):
        """Генерация файла out.mangle.rsc"""
        output_file = self.output_path / "out.mangle.rsc"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # Заголовок файла
                f.write("/ip firewall mangle\n")
                
                # Записываем mangle правила для каждого списка
                for list_name in list_names:
                    entry = MikrotikFormatter.format_mangle_entry(list_name, self.mark_name)
                    f.write(f"{entry}\n")
            
            logger.info(f"Файл mangle правил создан: {output_file}")
            
        except Exception as e:
            logger.error(f"Ошибка создания файла mangle правил: {e}")
    
    def generate_log_file(self, stats: Dict):
        """Генерация отчета в лог файл"""
        log_file = self.output_path / "out.log"
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("ОТЧЕТ О ВЫПОЛНЕНИИ ПРОГРАММЫ\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("СТАТИСТИКА ОБРАБОТКИ:\n")
                f.write("-" * 40 + "\n")
                
                for key, value in stats.items():
                    f.write(f"{key}: {value}\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("ВСЕ ФАЙЛЫ УСПЕШНО СОЗДАНЫ\n")
                f.write("=" * 60 + "\n")
            
            logger.info(f"Лог файл создан: {log_file}")
            
        except Exception as e:
            logger.error(f"Ошибка создания лог файла: {e}")

def setup_logging(log_file: Path, verbose: bool = False):
    """Настройка логирования в файл и консоль"""
    # Устанавливаем уровень логирования
    if verbose:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO
    
    logger.setLevel(logging_level)
    
    # Очищаем существующие обработчики
    logger.handlers.clear()
    
    # Создаем обработчик для консоли
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging_level)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Создаем обработчик для файла
    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging_level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.error(f"Не удалось создать лог файл {log_file}: {e}")

def interactive_mode():
    """Интерактивный режим работы программы"""
    print("=" * 60)
    print("MIKROTIK ADDRESS LIST GENERATOR")
    print("=" * 60)
    
    # Запрашиваем необходимые данные
    mark_name = input("Введите имя маркировки (mark name): ").strip()
    while not mark_name:
        print("Ошибка: Имя маркировки не может быть пустым!")
        mark_name = input("Введите имя маркировки (mark name): ").strip()
    
    while True:
        folder_path = input("Введите путь к исследуемой папке: ").strip()
        if Path(folder_path).exists():
            break
        print(f"Ошибка: Папка '{folder_path}' не существует!")
    
    while True:
        output_path = input("Введите путь для сохранения результатов: ").strip()
        output_path_obj = Path(output_path)
        try:
            output_path_obj.mkdir(parents=True, exist_ok=True)
            break
        except Exception as e:
            print(f"Ошибка создания папки: {e}. Попробуйте другой путь.")
    
    merge_file = input("Введите путь к файлу для объединения (или оставьте пустым): ").strip()
    if not merge_file:
        merge_file = None
    elif not Path(merge_file).exists():
        print(f"Предупреждение: Файл '{merge_file}' не существует. Будет продолжено без объединения.")
        merge_file = None
    
    verbose = input("Включить подробный вывод (debug режим)? (y/N): ").strip().lower()
    verbose_mode = verbose in ['y', 'yes', 'да', 'д']
    
    return {
        'mark_name': mark_name,
        'folder': folder_path,
        'output': output_path,
        'merge': merge_file,
        'verbose': verbose_mode
    }

def main():
    """Основная функция программы"""
    parser = argparse.ArgumentParser(
        description='Генератор списков адресов и mangle правил для Mikrotik',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s -m INTERNET -f ./input_folders -o ./output
  %(prog)s -m VPN -f ./my_lists -o ./routeros -merge ./existing.rsc
  
Интерактивный режим:
  %(prog)s
        """
    )
    
    parser.add_argument('-m', '--mark-name', help='Имя маркировки (routing mark)')
    parser.add_argument('-f', '--folder', help='Путь к исследуемой папке')
    parser.add_argument('-o', '--output', help='Путь для сохранения результатов')
    parser.add_argument('-merge', '--merge-file', help='Путь к файлу для объединения')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод (debug режим)')
    
    args = parser.parse_args()
    
    # Проверяем, есть ли аргументы
    if not any([args.mark_name, args.folder, args.output, args.merge_file, args.verbose]):
        # Режим интерактивного ввода
        params = interactive_mode()
        mark_name = params['mark_name']
        folder_path = params['folder']
        output_path = params['output']
        merge_file = params['merge']
        verbose = params['verbose']
    else:
        # Проверяем обязательные параметры
        if not all([args.mark_name, args.folder, args.output]):
            print("Ошибка: Необходимо указать все обязательные параметры!")
            print("Обязательные параметры: --mark-name, --folder, --output")
            print("Используйте --help для справки")
            sys.exit(1)
        
        mark_name = args.mark_name
        folder_path = args.folder
        output_path = args.output
        merge_file = args.merge_file
        verbose = args.verbose
    
    # Создаем пути
    folder_path_obj = Path(folder_path)
    output_path_obj = Path(output_path)
    
    # Создаем папку для результатов
    try:
        output_path_obj.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Ошибка создания папки результатов: {e}")
        sys.exit(1)
    
    # Настраиваем логирование
    log_file = output_path_obj / "out.log"
    setup_logging(log_file, verbose)
    
    logger.info("=" * 60)
    logger.info("ЗАПУСК ПРОГРАММЫ")
    logger.info("=" * 60)
    logger.info(f"Папка для сканирования: {folder_path}")
    logger.info(f"Папка для результатов: {output_path}")
    logger.info(f"Имя маркировки: {mark_name}")
    if merge_file:
        logger.info(f"Файл для объединения: {merge_file}")
    logger.info(f"Режим отладки: {'ВКЛЮЧЕН' if verbose else 'ВЫКЛЮЧЕН'}")
    logger.info("=" * 60)
    
    # Сканируем папку
    scanner = FolderScanner(folder_path_obj)
    if not scanner.scan():
        logger.error("Ошибка сканирования папки!")
        sys.exit(1)
    
    # Получаем оптимизированные списки
    ip_lists, domain_lists = scanner.get_optimized_lists()
    
    # Парсим существующий файл, если указан
    existing_lists = None
    if merge_file:
        merge_file_path = Path(merge_file)
        if merge_file_path.exists():
            logger.info(f"Парсинг существующего файла: {merge_file}")
            existing_lists = ExistingListsParser.parse_existing_file(merge_file_path)
            logger.info(f"Загружено {len(existing_lists)} списков из существующего файла")
        else:
            logger.warning(f"Файл для объединения не существует: {merge_file}")
    
    # Генерируем выходные файлы
    generator = OutputGenerator(output_path_obj, mark_name)
    generator.generate_files(ip_lists, domain_lists, existing_lists)
    
    # Собираем статистику
    stats = {
        "Обработано списков IP-адресов": len(ip_lists),
        "Обработано списков доменов": len(domain_lists),
        "Всего IP-записей": sum(len(entries) for entries in ip_lists.values()),
        "Всего доменных записей": sum(len(entries) for entries in domain_lists.values()),
        "Общее количество записей": sum(len(entries) for entries in ip_lists.values()) + 
                                   sum(len(entries) for entries in domain_lists.values()),
        "Созданные файлы": "out.lists.rsc, out.mangle.rsc, out.log"
    }
    
    # Выводим статистику
    logger.info("=" * 60)
    logger.info("СТАТИСТИКА ОБРАБОТКИ:")
    for key, value in stats.items():
        logger.info(f"{key}: {value}")
    logger.info("=" * 60)
    
    print("\n" + "=" * 60)
    print("ОБРАБОТКА ЗАВЕРШЕНА УСПЕШНО!")
    print("=" * 60)
    print(f"Результаты сохранены в папке: {output_path}")
    print(f"Созданные файлы:")
    print(f"  • {output_path_obj / 'out.lists.rsc'} - списки адресов")
    print(f"  • {output_path_obj / 'out.mangle.rsc'} - mangle правила")
    print(f"  • {output_path_obj / 'out.log'} - подробный лог выполнения")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Критическая ошибка: {e}")
        print(f"\nПроизошла критическая ошибка: {e}")
        print("Подробности смотрите в лог-файле")
        sys.exit(1)