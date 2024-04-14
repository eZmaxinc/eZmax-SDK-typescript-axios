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
import { UsergroupexternalResponseCompound } from './usergroupexternal-response-compound';

/**
 * Payload for GET /2/object/usergroupexternal/{pkiUsergroupexternalID}
 * @export
 * @interface UsergroupexternalGetObjectV2ResponseMPayload
 */
export interface UsergroupexternalGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {UsergroupexternalResponseCompound}
     * @memberof UsergroupexternalGetObjectV2ResponseMPayload
     */
    /*'objUsergroupexternal': UsergroupexternalResponseCompound;*/
    'objUsergroupexternal': UsergroupexternalResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupexternalResponseCompound } from './'
// @ts-ignore
import { ValidationObjectUsergroupexternalResponseCompound } from './'

/**
 * @export 
 * A UsergroupexternalGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetObjectV2ResponseMPayload
 */
export class DataObjectUsergroupexternalGetObjectV2ResponseMPayload {
   objUsergroupexternal:UsergroupexternalResponseCompound = new DataObjectUsergroupexternalResponseCompound()
}

/**
 * @export 
 * A UsergroupexternalGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupexternalGetObjectV2ResponseMPayload
 */
export class ValidationObjectUsergroupexternalGetObjectV2ResponseMPayload {
   objUsergroupexternal = new ValidationObjectUsergroupexternalResponseCompound()
} 


