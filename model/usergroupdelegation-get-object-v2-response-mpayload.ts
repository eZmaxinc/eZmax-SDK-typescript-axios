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
import { UsergroupdelegationResponseCompound } from './usergroupdelegation-response-compound';

/**
 * Payload for GET /2/object/usergroupdelegation/{pkiUsergroupdelegationID}
 * @export
 * @interface UsergroupdelegationGetObjectV2ResponseMPayload
 */
export interface UsergroupdelegationGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {UsergroupdelegationResponseCompound}
     * @memberof UsergroupdelegationGetObjectV2ResponseMPayload
     */
    'objUsergroupdelegation': UsergroupdelegationResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupdelegationResponseCompound } from './'
// @ts-ignore
import { ValidationObjectUsergroupdelegationResponseCompound } from './'

/**
 * @export 
 * A UsergroupdelegationGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupdelegationGetObjectV2ResponseMPayload
 */
export class DataObjectUsergroupdelegationGetObjectV2ResponseMPayload {
   objUsergroupdelegation:UsergroupdelegationResponseCompound = new DataObjectUsergroupdelegationResponseCompound()
}

/**
 * @export 
 * A UsergroupdelegationGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupdelegationGetObjectV2ResponseMPayload
 */
export class ValidationObjectUsergroupdelegationGetObjectV2ResponseMPayload {
   objUsergroupdelegation = new ValidationObjectUsergroupdelegationResponseCompound()
} 


