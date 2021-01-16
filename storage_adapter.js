'use strict';

const toSnakeCase = require('to-snake-case');

// const logger = require('tracer').colorConsole();
const logger = require('./logger');
const knex = require('./db').knex;

// All types except "Client"
const VOLATILE_TYPES = [
    'Session',
    'AccessToken',
    'AuthorizationCode',
    'RefreshToken',
    'ClientCredentials',
    'InitialAccessToken',
    'RegistrationAccessToken',
    'DeviceCode',
    'Interaction',
    'ReplayDetection',
    'PushedAuthorizationRequest',
];

// Purge after every purge_period upserts
let purge_period = 1000;
let upserts_count = 0;

// Note: From the author of "oidc-provider" the MongoDB storage adapter is the
// only one that can be considered a reference and that should be used as a
// model.
class StorageAdapter {

    /**
     * Creates an instance of this adapter for an oidc-provider model.
     *
     * @constructor
     * @param {string} name Name of the oidc-provider model. One of "Session", "AccessToken",
     * "AuthorizationCode", "RefreshToken", "ClientCredentials", "Client", "InitialAccessToken",
     * "RegistrationAccessToken", "DeviceCode", "Interaction",
     * "ReplayDetection", or "PushedAuthorizationRequest".
     */
    constructor(name) {
        this.table_name = `oidc.${toSnakeCase(name)}`;
    }

    /**
     * Updates or Creates an instance of an oidc-provider model.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error
     *   when encountered.
     * @param {string} id Identifier that oidc-provider will use to reference
     *   this model instance for future operations
     * @param {Object} payload Object with all properties intended for storage
     * @param {number} expiresIn number of seconds intended for this model to be stored
     */
    async upsert(id, payload, expiresIn) {
        // Favoring reads over writes, since the OP is more often called for
        // verifying than for authenticating (the latter implying writes) and do
        // thus performing purgeExpired only when some data is inserted or
        // updated and not when calling "find", "findByUid" or "findByUserCode".
        if (++upserts_count >= purge_period) {
            upserts_count = 0;
            await this.purgeExpired();
        }

        const update_props = {
            data: payload,
        };

        if (expiresIn) {
            update_props.expires_at = new Date(Date.now() + expiresIn * 1000);
        }

        const record = await knex(this.table_name).where({id});
        if (record.length) {
            update_props.updated_at = new Date();
            await knex(this.table_name)
                .where({id})
                .update(update_props);
        } else {
            update_props.id = id;
            await knex(this.table_name).insert(update_props);
        }
    }

    /**
     * Returns previously stored instance of an oidc-provider model.
     *
     * @return {Promise} Promise fulfilled with either Object (when found and
     *   not dropped yet due to expiration) or falsy value when not found
     *   anymore. Rejected with error when encountered.
     * @param {string} id Identifier of oidc-provider model
     */
    async find(id) {
        const record = await knex(this.table_name).where((qb) => {
            qb.where(function() {
                this.where({id});
            }).andWhere(function() {
                this.whereNull('expires_at').orWhere('expires_at', '>', new Date());
            });
        });

        if (!record.length) {
            return null;
        }

        return record[0].data;
    }

    /**
     * Return previously stored instance of Session by its uid reference property.
     *
     * @return {Promise} Promise fulfilled with the stored session object (when found and not
     * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
     * when encountered.
     * @param {string} uid the uid value associated with a Session instance
     */
    async findByUid(uid) {
        const record = await knex(this.table_name).where((qb) => {
            qb.where(function() {
                this.where('data', '@>', `{"uid": "${uid}"}`);
            }).andWhere(function() {
                this.whereNull('expires_at').orWhere('expires_at', '>', new Date());
            });
        });

        if (!record.length) {
            return null;
        }

        return record[0].data;
    }

    /**
     * Return previously stored instance of DeviceCode by the end-user entered user code.
     * You only need this method for the deviceFlow feature.
     *
     * @param {string} userCode the user_code value associated with a DeviceCode instance
     * @return {Promise} Promise fulfilled with the stored device code object (when found and not
     * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
     * when encountered.
     *
     */
    async findByUserCode(userCode) {
        const record = await knex(this.table_name).where((qb) => {
            qb.where(function() {
                this.where('data', '@>', `{"userCode": "${userCode}"}`);
            }).andWhere(function() {
                this.whereNull('expires_at').orWhere('expires_at', '>', new Date());
            });
        });

        if (!record.length) {
            return null;
        }

        return record[0].data;
    }

    /**
     * Mark a stored oidc-provider model as consumed (not yet expired though!). Future finds for this
     * id should be fulfilled with an object containing additional property named "consumed" with a
     * truthy value (timestamp, date, boolean, etc).
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
     * encountered.
     * @param {string} id Identifier of oidc-provider model
     */
    async consume(id) {
        const record = await knex(this.table_name).where({id});
        const data = record[0].data;
        data.consumed = new Date().toISOString();
        await knex(this.table_name)
            .where({id})
            .update({data});
    }

    /**
     * Destroy/Drop/Remove a stored oidc-provider model. Future finds for this id should be fulfilled
     * with falsy values.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
     * encountered.
     * @param {string} id Identifier of oidc-provider model
     */
    async destroy(id) {
        await knex(this.table_name)
            .where({id})
            .del();
    }

    /**
     * Destroy/Drop/Remove a stored oidc-provider model by its grantId property reference. Future
     * finds for all tokens having this grantId value should be fulfilled with falsy values.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
     * encountered.
     * @param {string} grantId the grantId value associated with a this model's instance
     */
    async revokeByGrantId(grantId) {
        await knex(this.table_name)
            .where('data', '@>', `{"grantId": "${grantId}"}`)
            .del();
    }

    // *************************************************************************
    // Methods non-required by the oidc-provider framework
    // *************************************************************************

    /**
     * Purges all the records of this oidc-provider model.
     *
     * Commodity method, but not required by the oidc-provider framework.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error
     *   when encountered.
     */
    async purgeExpired() {
        logger.debug('purging');
        await knex(this.table_name)
            .where('expires_at', '<=', new Date())
            .del();
    }

    async destroyAll() {
        await knex(this.table_name).del();
    }

    /**
     * Returns all, or a selection, of the records of this oidc-provider model.
     *
     * Commodity method, but not required by the oidc-provider framework.
     *
     * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error
     *   when encountered.
     */
    get({ids = undefined, options = {order_by: ['updated_at', 'desc']}} = {}) {
        return knex(this.table_name)
            .where((qb) => {
                if (ids) {
                    qb.whereIn('id', ids);
                }
            })
            .orderBy(...options.order_by);
    }

    // Static methods

    static setPurgePeriod(count) {
        purge_period = count;
    }

    static cleanVolatileData() {
        return Promise.all(VOLATILE_TYPES.map((volatile_type_name) => {
            const volatile_type = new StorageAdapter(volatile_type_name);
            return volatile_type.destroyAll();
        }));
    }

}

module.exports = StorageAdapter;
