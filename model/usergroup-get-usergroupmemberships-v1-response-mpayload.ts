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
import { UsergroupmembershipResponseCompound } from './usergroupmembership-response-compound';

/**
 * Response for GET /1/object/usergroup/{pkiUsergroupID}/getUsergroupmemberships
 * @export
 * @interface UsergroupGetUsergroupmembershipsV1ResponseMPayload
 */
export interface UsergroupGetUsergroupmembershipsV1ResponseMPayload {
    /**
     * 
     * @type {Array<UsergroupmembershipResponseCompound>}
     * @memberof UsergroupGetUsergroupmembershipsV1ResponseMPayload
     */
    'a_objUsergroupmembership': Array<UsergroupmembershipResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupGetUsergroupmembershipsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload
 */
export class DataObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload {
   a_objUsergroupmembership:Array<UsergroupmembershipResponseCompound> = []
}

/**
 * @export 
 * A UsergroupGetUsergroupmembershipsV1ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload
 */
export class ValidationObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload {
   a_objUsergroupmembership = {
      type: 'array',
      required: true
   }
} 


