const PREFIX = "/api";

const req = (url, method, options = {}) => {
  const { body } = options;

  return fetch((PREFIX + url).replace(/\/\/$/, ""), {
    ...options,
    body: body ? JSON.stringify(body) : null,
    headers: {
      ...options.headers,
      ...(body
        ? {
            "Content-Type": "application/json",
          }
        : null),
    },
  }).then((res) => {
    return res.ok
      ? res.json()
      : res.text().then((message) => {
          throw new Error(message);
        });
  });
};

export const getNotes = ({ age, search, page } = {}) => {
  return req(`/notes?age=${age}&search=${search}&page=${page}`, "getNotes");
};

export const createNote = (title, text) => {
  const options = {
    method: "post",
    body: {
      title: title,
      text: text,
    },
  };
  return req("/notes", "createNote", options);
};

export const getNote = (id) => {
  return req(`/note/${id}`, "getNote");
};

export const archiveNote = (id) => {
  const options = {
    method: "post",
    body: {
      isArchived: true,
    },
  };
  return req(`/note/${id}/archive`, "archiveNote", options);
};

export const unarchiveNote = (id) => {
  const options = {
    method: "post",
    body: {
      isArchived: false,
    },
  };
  return req(`/note/${id}/archive`, "unarchiveNote", options);
};

export const editNote = (id, title, text) => {
  const options = {
    method: "post",
    body: {
      title: title,
      text: text,
    },
  };
  return req(`/note/${id}/edit`, "editNote", options);
};

export const deleteNote = (id) => {
  const options = {
    method: "delete",
  };
  return req(`/note/${id}`, "deleteNote", options);
};

export const deleteAllArchived = () => {
  const options = {
    method: "delete",
  };
  return req(`/note?deleteAll=true`, "deleteAllArchived", options);
};

export const notePdfUrl = (id) => {
  console.log(id);
};
