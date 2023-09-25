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
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

/**
 * Payload for GET /2/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID}
 * @export
 * @interface EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload
 */
export interface EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipResponseCompound}
     * @memberof EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload
     */
    'objEzsigntemplatepackagesignermembership': EzsigntemplatepackagesignermembershipResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackagesignermembershipResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignermembershipResponseCompound } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload
 */
export class DataObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload {
   objEzsigntemplatepackagesignermembership:EzsigntemplatepackagesignermembershipResponseCompound = new DataObjectEzsigntemplatepackagesignermembershipResponseCompound()
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload {
   objEzsigntemplatepackagesignermembership = new ValidationObjectEzsigntemplatepackagesignermembershipResponseCompound()
} 


