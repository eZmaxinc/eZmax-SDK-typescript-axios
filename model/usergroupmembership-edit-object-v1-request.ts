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
import { UsergroupmembershipRequestCompound } from './usergroupmembership-request-compound';

/**
 * Request for PUT /1/object/usergroupmembership/{pkiUsergroupmembershipID}
 * @export
 * @interface UsergroupmembershipEditObjectV1Request
 */
export interface UsergroupmembershipEditObjectV1Request {
    /**
     * 
     * @type {UsergroupmembershipRequestCompound}
     * @memberof UsergroupmembershipEditObjectV1Request
     */
    'objUsergroupmembership': UsergroupmembershipRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupmembershipRequestCompound } from './'
// @ts-ignore
import { ValidationObjectUsergroupmembershipRequestCompound } from './'

/**
 * @export 
 * A UsergroupmembershipEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipEditObjectV1Request
 */
export class DataObjectUsergroupmembershipEditObjectV1Request {
   objUsergroupmembership:UsergroupmembershipRequestCompound = new DataObjectUsergroupmembershipRequestCompound()
}

/**
 * @export 
 * A UsergroupmembershipEditObjectV1Request Validation Object
 * @class ValidationObjectUsergroupmembershipEditObjectV1Request
 */
export class ValidationObjectUsergroupmembershipEditObjectV1Request {
   objUsergroupmembership = new ValidationObjectUsergroupmembershipRequestCompound()
} 

