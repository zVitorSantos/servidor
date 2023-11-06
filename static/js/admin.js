$(document).ready(function() {
    var tbodyEl = $('table tbody');
    function checkUserPermission(callback) {
        $.ajax({
            url: '/check-permission',
            type: 'GET',
            xhrFields: {
                withCredentials: true
            },
            success: function(response) {
                // O servidor deve responder com { 'isAllowed': true } para um usuário autorizado
                callback(response.isAllowed);
            },
            error: function(xhr) {
                // Se houver algum erro (como o usuário não estar autenticado ou não ter permissão), trate aqui
                if (xhr.status === 401) {
                    // Não autenticado
                    alert('Você não está autenticado. Por favor, faça o login.');
                } else if (xhr.status === 403) {
                    // Não autorizado
                    alert('Você não tem permissão para acessar esta funcionalidade.');
                } else {
                    // Outro erro
                    alert('Ocorreu um erro ao verificar as permissões: ' + xhr.statusText);
                }
            }
        });
    }

    // Função para atualizar a tabela de usuários
    function updateUsersTable() {
        $.ajax({
            url: '/users',
            type: 'GET',
            dataType: 'json',
            xhrFields: {
                withCredentials: true
            },
            success: function(response) {
                console.log(response);
                if (Array.isArray(response)) {
                    var tbodyEl = $('table tbody');
                    tbodyEl.empty();
                    response.forEach(function(user) {
                        tbodyEl.append(`
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.name}</td>
                                <td>${user.username}</td>
                                <td>${user.email}</td>
                                <td>${user.is_admin ? 'Sim' : 'Não'}</td>
                                <td>
                                    <button class="btn btn-sm btn-outline-danger delete-btn" data-user-id="${user.id}">
                                        <i class="bi bi-trash-fill"></i>
                                    </button>
                                </td>
                            </tr>
                        `);
                    });
                } else {
                    console.error('A resposta não é um array:', response);
                }
            },
            error: function(xhr, status, error) {
                handleAjaxError(xhr, status, error);
            }
        });
    }

    // Função para tratar erros de AJAX
    function handleAjaxError(xhr, status, error) {
        if (xhr.status === 401) {
            // Verifique se não está na página de login antes de redirecionar
            if (window.location.pathname !== '/login') {
                console.error('Não autenticado: redirecionando para o login.');
                window.location.href = '/login';
            }
        } else if (xhr.status === 403) {
            console.error('Acesso negado: redirecionando para a página principal.');
            window.location.href = '/';
        } else if (xhr.status === 500) {
            console.error('Erro interno do servidor: contate o administrador.');
        } else {
            console.error('Erro na comunicação com o servidor: ' + xhr.statusText);
        }
    }

    // Função para mostrar mensagens de erro
    function showError(message) {
        $('#error-message').text(message).show();
    }

    // Manipulador de eventos para o botão de registro de usuário
    $('#register_button').on('click', function() {
        var name = $('#userName').val().trim();
        var username = $('#userUsername').val().trim();
        var email = $('#userEmail').val().trim();
        var password = $('#password').val();
        var confirmPassword = $('#confirm_password').val();
        var isAdmin = $('#isAdmin').is(':checked');

        if(password !== confirmPassword) {
            showError('As senhas não coincidem.');
            return;
        }

        var formData = {
            name: name,
            username: username,
            email: email,
            password: password,
            is_admin: isAdmin
        };

        $.ajax({
            url: '/register',
            type: 'POST',
            contentType: 'application/x-www-form-urlencoded',
            data: formData,
            success: function(response) {
                if(response.success) {
                    checkUserPermission(function(isPermitted) {
                        if (isPermitted) {
                            updateUsersTable();
                            $('#registerUserModal').modal('hide');
                            alert('Usuário criado com sucesso!');
                        } else {
                            showError('Você não tem permissão para criar um usuário.');
                        }
                    });
                } else {
                    showError(response.message || 'Erro ao criar o usuário. Tente novamente.');
                }
            },
            error: function(xhr) {
                if(xhr.status === 409) {
                    showError('Nome de usuário ou email já cadastrado.');
                } else {
                    showError('Erro na comunicação com o servidor: ' + xhr.statusText);
                }
            }
        });
    });

    tbodyEl.on('click', '.delete-btn', function() {
        var userId = $(this).data('user-id');
        if (confirm('Tem certeza que deseja apagar o usuário?')) {
            deleteUser(userId);
        }
    });

    function deleteUser(userId) {
        $.ajax({
            url: '/delete-user/' + userId,
            type: 'POST',  // Embora o método correto seja DELETE, alguns servidores/browsers não suportam
            success: function(response) {
                if(response.success) {
                    alert('Usuário apagado com sucesso!');
                    updateUsersTable();
                } else {
                    showError(response.message || 'Erro ao apagar o usuário. Tente novamente.');
                }
            },
            error: function(xhr) {
                showError('Erro na comunicação com o servidor: ' + xhr.statusText);
            }
        });
    }

    // Chama a função para atualizar a tabela se o usuário estiver autorizado
    checkUserPermission(function(isPermitted) {
        if (isPermitted) {
            updateUsersTable();
        } else {
            showError('Você não tem permissão para visualizar esta tabela.');
        }
    });
});