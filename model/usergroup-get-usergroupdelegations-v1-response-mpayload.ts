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
import { UsergroupdelegationResponseCompound } from './usergroupdelegation-response-compound';

/**
 * Response for GET /1/object/usergroup/{pkiUsergroupID}/getUsergroupdelegations
 * @export
 * @interface UsergroupGetUsergroupdelegationsV1ResponseMPayload
 */
export interface UsergroupGetUsergroupdelegationsV1ResponseMPayload {
    /**
     * 
     * @type {Array<UsergroupdelegationResponseCompound>}
     * @memberof UsergroupGetUsergroupdelegationsV1ResponseMPayload
     */
    'a_objUsergroupdelegation': Array<UsergroupdelegationResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupGetUsergroupdelegationsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetUsergroupdelegationsV1ResponseMPayload
 */
export class DataObjectUsergroupGetUsergroupdelegationsV1ResponseMPayload {
   a_objUsergroupdelegation:Array<UsergroupdelegationResponseCompound> = []
}

/**
 * @export 
 * A UsergroupGetUsergroupdelegationsV1ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupGetUsergroupdelegationsV1ResponseMPayload
 */
export class ValidationObjectUsergroupGetUsergroupdelegationsV1ResponseMPayload {
   a_objUsergroupdelegation = {
      type: 'array',
      required: true
   }
} 


