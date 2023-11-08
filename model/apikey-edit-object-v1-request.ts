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


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyRequestCompound } from './apikey-request-compound';

/**
 * Request for PUT /1/object/apikey/{pkiApikeyID}
 * @export
 * @interface ApikeyEditObjectV1Request
 */
export interface ApikeyEditObjectV1Request {
    /**
     * 
     * @type {ApikeyRequestCompound}
     * @memberof ApikeyEditObjectV1Request
     */
    'objApikey': ApikeyRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectApikeyRequestCompound } from './'
// @ts-ignore
import { ValidationObjectApikeyRequestCompound } from './'

/**
 * @export 
 * A ApikeyEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyEditObjectV1Request
 */
export class DataObjectApikeyEditObjectV1Request {
   objApikey:ApikeyRequestCompound = new DataObjectApikeyRequestCompound()
}

/**
 * @export 
 * A ApikeyEditObjectV1Request Validation Object
 * @class ValidationObjectApikeyEditObjectV1Request
 */
export class ValidationObjectApikeyEditObjectV1Request {
   objApikey = new ValidationObjectApikeyRequestCompound()
} 

