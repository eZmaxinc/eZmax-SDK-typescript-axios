/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload } from './ezsigntemplatepackagesignermembership-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf
 */
export interface EzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf
 */
export class DataObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf {
   mPayload:EzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplatepackagesignermembershipGetObjectV2ResponseMPayload()
} 


