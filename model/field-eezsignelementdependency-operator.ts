/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The operator of the Ezsignelementdependency
 * @export
 * @enum {string}
 */

export const FieldEEzsignelementdependencyOperator = {
    eq: 'eq',
    neq: 'neq',
    gt: 'gt',
    gte: 'gte',
    lt: 'lt',
    lte: 'lte',
    in: 'in',
    nin: 'nin',
    rg: 'rg',
    like: 'like',
    between: 'between'
} as const;

export type FieldEEzsignelementdependencyOperator = typeof FieldEEzsignelementdependencyOperator[keyof typeof FieldEEzsignelementdependencyOperator];


