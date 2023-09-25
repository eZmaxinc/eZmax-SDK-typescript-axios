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
 * Request for PUT /1/object/usergroup/{pkiUsergroupID}/editUsergroupdelegations
 * @export
 * @interface UsergroupEditUsergroupdelegationsV1Request
 */
export interface UsergroupEditUsergroupdelegationsV1Request {
    /**
     * 
     * @type {Array<UsergroupdelegationRequestCompound>}
     * @memberof UsergroupEditUsergroupdelegationsV1Request
     */
    'a_objUsergroupdelegation': Array<UsergroupdelegationRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupEditUsergroupdelegationsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditUsergroupdelegationsV1Request
 */
export class DataObjectUsergroupEditUsergroupdelegationsV1Request {
   a_objUsergroupdelegation:Array<UsergroupdelegationRequestCompound> = []
}

/**
 * @export 
 * A UsergroupEditUsergroupdelegationsV1Request Validation Object
 * @class ValidationObjectUsergroupEditUsergroupdelegationsV1Request
 */
export class ValidationObjectUsergroupEditUsergroupdelegationsV1Request {
   a_objUsergroupdelegation = {
      type: 'array',
      required: true
   }
} 


