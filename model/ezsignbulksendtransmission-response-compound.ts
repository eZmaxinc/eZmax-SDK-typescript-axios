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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomEzsignfoldertransmissionResponse } from './custom-ezsignfoldertransmission-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignbulksendtransmissionResponse } from './ezsignbulksendtransmission-response';

/**
 * @type EzsignbulksendtransmissionResponseCompound
 * An Ezsignbulksendtransmission Object and children to create a complete structure
 * @export
 */
/*export type EzsignbulksendtransmissionResponseCompound = EzsignbulksendtransmissionResponse;*/
export interface EzsignbulksendtransmissionResponseCompound {
    /**
     * 
     * @type {Array<CustomEzsignfoldertransmissionResponse>}
     * @memberof EzsignbulksendtransmissionResponseCompound
     */
    a_objEzsignfoldertransmission:Array<CustomEzsignfoldertransmissionResponse> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendtransmissionResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionResponseCompound
 */
export class DataObjectEzsignbulksendtransmissionResponseCompound {
    a_objEzsignfoldertransmission:Array<CustomEzsignfoldertransmissionResponse> = []
}

/**
 * @export 
 * A EzsignbulksendtransmissionResponseCompound Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionResponseCompound
 */
export class ValidationObjectEzsignbulksendtransmissionResponseCompound {
   a_objEzsignfoldertransmission = {
      type: 'array',
      required: true
   }
} 


