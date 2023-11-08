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
import { EzsignsignergroupmembershipResponseCompound } from './ezsignsignergroupmembership-response-compound';

/**
 * Payload for GET /2/object/ezsignsignergroupmembership/{pkiEzsignsignergroupmembershipID}
 * @export
 * @interface EzsignsignergroupmembershipGetObjectV2ResponseMPayload
 */
export interface EzsignsignergroupmembershipGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignsignergroupmembershipResponseCompound}
     * @memberof EzsignsignergroupmembershipGetObjectV2ResponseMPayload
     */
    'objEzsignsignergroupmembership': EzsignsignergroupmembershipResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignergroupmembershipResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignsignergroupmembershipResponseCompound } from './'

/**
 * @export 
 * A EzsignsignergroupmembershipGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupmembershipGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignsignergroupmembershipGetObjectV2ResponseMPayload {
   objEzsignsignergroupmembership:EzsignsignergroupmembershipResponseCompound = new DataObjectEzsignsignergroupmembershipResponseCompound()
}

/**
 * @export 
 * A EzsignsignergroupmembershipGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsignergroupmembershipGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignsignergroupmembershipGetObjectV2ResponseMPayload {
   objEzsignsignergroupmembership = new ValidationObjectEzsignsignergroupmembershipResponseCompound()
} 

