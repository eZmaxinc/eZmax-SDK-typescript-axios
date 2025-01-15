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
import type { SubnetResponseCompound } from './subnet-response-compound';

/**
 * Payload for GET /2/object/subnet/{pkiSubnetID}
 * @export
 * @interface SubnetGetObjectV2ResponseMPayload
 */
export interface SubnetGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {SubnetResponseCompound}
     * @memberof SubnetGetObjectV2ResponseMPayload
     */
    /*'objSubnet': SubnetResponseCompound;*/
    'objSubnet': SubnetResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectSubnetResponseCompound } from './'
// @ts-ignore
import { ValidationObjectSubnetResponseCompound } from './'

/**
 * @export 
 * A SubnetGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSubnetGetObjectV2ResponseMPayload
 */
export class DataObjectSubnetGetObjectV2ResponseMPayload {
   objSubnet:SubnetResponseCompound = new DataObjectSubnetResponseCompound()
}

/**
 * @export 
 * A SubnetGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectSubnetGetObjectV2ResponseMPayload
 */
export class ValidationObjectSubnetGetObjectV2ResponseMPayload {
   objSubnet = new ValidationObjectSubnetResponseCompound()
} 


