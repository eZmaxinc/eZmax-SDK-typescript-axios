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
import { UsergroupdelegationRequestCompound } from './usergroupdelegation-request-compound';

/**
 * Request for POST /1/object/usergroupdelegation
 * @export
 * @interface UsergroupdelegationCreateObjectV1Request
 */
export interface UsergroupdelegationCreateObjectV1Request {
    /**
     * 
     * @type {Array<UsergroupdelegationRequestCompound>}
     * @memberof UsergroupdelegationCreateObjectV1Request
     */
    'a_objUsergroupdelegation': Array<UsergroupdelegationRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupdelegationCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupdelegationCreateObjectV1Request
 */
export class DataObjectUsergroupdelegationCreateObjectV1Request {
   a_objUsergroupdelegation:Array<UsergroupdelegationRequestCompound> = []
}

/**
 * @export 
 * A UsergroupdelegationCreateObjectV1Request Validation Object
 * @class ValidationObjectUsergroupdelegationCreateObjectV1Request
 */
export class ValidationObjectUsergroupdelegationCreateObjectV1Request {
   a_objUsergroupdelegation = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


