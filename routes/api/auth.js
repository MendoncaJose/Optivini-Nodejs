import express from 'express';
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import auth from '../../middleware/auth';
import jwt from 'jsonwebtoken';
import config from 'config';
import { check, validationResult } from 'express-validator';
import User from '../../models/User';

const router = Router();

// @route    GET api/auth
// @desc     Get user by token
// @access   Private

router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).sendStatus('Server error');
  }
});

// @route    POST api/auth
// @desc     Authenticate user & get token
// @access   Public

router.post(
  '/',
  check('user', 'Introduza um username válido').exists(),
  check('password', 'Introduza um password válido').exists(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;

    try {
      let user = await User.findOne({ username });

      if (!user) {
        return res
          .status(404)
          .json({ errors: [{ msg: 'Credenciais Inválidas' }] });
      }
      const isMath = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'crediciais Invalidas' }] });
      }

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: '5 days' },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).sendStatus('Erro de Servidor');
    }
  }
);
