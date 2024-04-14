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
import { EzsignsignergroupmembershipRequestCompound } from './ezsignsignergroupmembership-request-compound';

/**
 * Request for PUT /1/object/ezsignsignergroup/{pkiEzsignsignergroupID}/editEzsignsignergroupmemberships
 * @export
 * @interface EzsignsignergroupEditEzsignsignergroupmembershipsV1Request
 */
export interface EzsignsignergroupEditEzsignsignergroupmembershipsV1Request {
    /**
     * 
     * @type {Array<EzsignsignergroupmembershipRequestCompound>}
     * @memberof EzsignsignergroupEditEzsignsignergroupmembershipsV1Request
     */
    /*'a_objEzsignsignergroupmembership': Array<EzsignsignergroupmembershipRequestCompound>;*/
    'a_objEzsignsignergroupmembership': Array<EzsignsignergroupmembershipRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupEditEzsignsignergroupmembershipsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Request
 */
export class DataObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Request {
   a_objEzsignsignergroupmembership:Array<EzsignsignergroupmembershipRequestCompound> = []
}

/**
 * @export 
 * A EzsignsignergroupEditEzsignsignergroupmembershipsV1Request Validation Object
 * @class ValidationObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Request
 */
export class ValidationObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Request {
   a_objEzsignsignergroupmembership = {
      type: 'array',
      required: true
   }
} 


