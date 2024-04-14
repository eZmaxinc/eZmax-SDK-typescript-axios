/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyResponseCompound } from './apikey-response-compound';

/**
 * Response for GET /1/object/apikey/{pkiApikeyID}/regenerate
 * @export
 * @interface ApikeyRegenerateV1ResponseMPayload
 */
export interface ApikeyRegenerateV1ResponseMPayload {
    /**
     * 
     * @type {ApikeyResponseCompound}
     * @memberof ApikeyRegenerateV1ResponseMPayload
     */
    /*'objApikey': ApikeyResponseCompound;*/
    'objApikey': ApikeyResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectApikeyResponseCompound } from './'
// @ts-ignore
import { ValidationObjectApikeyResponseCompound } from './'

/**
 * @export 
 * A ApikeyRegenerateV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyRegenerateV1ResponseMPayload
 */
export class DataObjectApikeyRegenerateV1ResponseMPayload {
   objApikey:ApikeyResponseCompound = new DataObjectApikeyResponseCompound()
}

/**
 * @export 
 * A ApikeyRegenerateV1ResponseMPayload Validation Object
 * @class ValidationObjectApikeyRegenerateV1ResponseMPayload
 */
export class ValidationObjectApikeyRegenerateV1ResponseMPayload {
   objApikey = new ValidationObjectApikeyResponseCompound()
} 


