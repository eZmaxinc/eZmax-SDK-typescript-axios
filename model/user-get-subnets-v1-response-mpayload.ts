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
import type { SubnetResponseCompound } from './subnet-response-compound';

/**
 * Response for GET /1/object/user/{pkiUserID}/getSubnets
 * @export
 * @interface UserGetSubnetsV1ResponseMPayload
 */
export interface UserGetSubnetsV1ResponseMPayload {
    /**
     * 
     * @type {Array<SubnetResponseCompound>}
     * @memberof UserGetSubnetsV1ResponseMPayload
     */
    /*'a_objSubnet': Array<SubnetResponseCompound>;*/
    'a_objSubnet': Array<SubnetResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserGetSubnetsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserGetSubnetsV1ResponseMPayload
 */
export class DataObjectUserGetSubnetsV1ResponseMPayload {
   a_objSubnet:Array<SubnetResponseCompound> = []
}

/**
 * @export 
 * A UserGetSubnetsV1ResponseMPayload Validation Object
 * @class ValidationObjectUserGetSubnetsV1ResponseMPayload
 */
export class ValidationObjectUserGetSubnetsV1ResponseMPayload {
   a_objSubnet = {
      type: 'array',
      required: true
   }
} 


