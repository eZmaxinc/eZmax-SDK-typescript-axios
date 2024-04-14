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
import { EzsignsignergroupmembershipResponseCompound } from './ezsignsignergroupmembership-response-compound';

/**
 * Response for GET /1/object/ezsignsignergroup/{pkiEzsignsignergroupID}/getEzsignsignergroupmemberships
 * @export
 * @interface EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload
 */
export interface EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignergroupmembershipResponseCompound>}
     * @memberof EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload
     */
    /*'a_objEzsignsignergroupmembership': Array<EzsignsignergroupmembershipResponseCompound>;*/
    'a_objEzsignsignergroupmembership': Array<EzsignsignergroupmembershipResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload
 */
export class DataObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload {
   a_objEzsignsignergroupmembership:Array<EzsignsignergroupmembershipResponseCompound> = []
}

/**
 * @export 
 * A EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload
 */
export class ValidationObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload {
   a_objEzsignsignergroupmembership = {
      type: 'array',
      required: true
   }
} 


