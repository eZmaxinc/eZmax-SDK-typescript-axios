/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { UsergroupexternalmembershipResponseCompound } from './usergroupexternalmembership-response-compound';

/**
 * Response for GET /1/object/usergroupexternal/{pkiUsergroupexternalID}/getUsergroupexternalmemberships
 * @export
 * @interface UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload
 */
export interface UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload {
    /**
     * 
     * @type {Array<UsergroupexternalmembershipResponseCompound>}
     * @memberof UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload
     */
    /*'a_objUsergroupexternalmembership': Array<UsergroupexternalmembershipResponseCompound>;*/
    'a_objUsergroupexternalmembership': Array<UsergroupexternalmembershipResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload
 */
export class DataObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload {
   a_objUsergroupexternalmembership:Array<UsergroupexternalmembershipResponseCompound> = []
}

/**
 * @export 
 * A UsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload Validation Object
 * @class ValidationObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload
 */
export class ValidationObjectUsergroupexternalGetUsergroupexternalmembershipsV1ResponseMPayload {
   a_objUsergroupexternalmembership = {
      type: 'array',
      required: true
   }
} 


