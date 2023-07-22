/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UsergroupRequestCompound } from './usergroup-request-compound';

/**
 * Request for PUT /1/object/usergroup/{pkiUsergroupID}
 * @export
 * @interface UsergroupEditObjectV1Request
 */
export interface UsergroupEditObjectV1Request {
    /**
     * 
     * @type {UsergroupRequestCompound}
     * @memberof UsergroupEditObjectV1Request
     */
    'objUsergroup': UsergroupRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupRequestCompound } from './'
// @ts-ignore
import { ValidationObjectUsergroupRequestCompound } from './'

/**
 * @export 
 * A UsergroupEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditObjectV1Request
 */
export class DataObjectUsergroupEditObjectV1Request {
   objUsergroup:UsergroupRequestCompound = new DataObjectUsergroupRequestCompound()
}

/**
 * @export 
 * A UsergroupEditObjectV1Request Validation Object
 * @class ValidationObjectUsergroupEditObjectV1Request
 */
export class ValidationObjectUsergroupEditObjectV1Request {
   objUsergroup = new ValidationObjectUsergroupRequestCompound()
} 


