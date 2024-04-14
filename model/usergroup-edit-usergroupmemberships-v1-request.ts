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
import { UsergroupmembershipRequestCompound } from './usergroupmembership-request-compound';

/**
 * Request for PUT /1/object/usergroup/{pkiUsergroupID}/editUsergroupmemberships
 * @export
 * @interface UsergroupEditUsergroupmembershipsV1Request
 */
export interface UsergroupEditUsergroupmembershipsV1Request {
    /**
     * 
     * @type {Array<UsergroupmembershipRequestCompound>}
     * @memberof UsergroupEditUsergroupmembershipsV1Request
     */
    /*'a_objUsergroupmembership': Array<UsergroupmembershipRequestCompound>;*/
    'a_objUsergroupmembership': Array<UsergroupmembershipRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupEditUsergroupmembershipsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditUsergroupmembershipsV1Request
 */
export class DataObjectUsergroupEditUsergroupmembershipsV1Request {
   a_objUsergroupmembership:Array<UsergroupmembershipRequestCompound> = []
}

/**
 * @export 
 * A UsergroupEditUsergroupmembershipsV1Request Validation Object
 * @class ValidationObjectUsergroupEditUsergroupmembershipsV1Request
 */
export class ValidationObjectUsergroupEditUsergroupmembershipsV1Request {
   a_objUsergroupmembership = {
      type: 'array',
      required: true
   }
} 


