/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackagemembershipRequest } from './ezsigntemplatepackagemembership-request';

/**
 * @type EzsigntemplatepackagemembershipRequestCompound
 * A Ezsigntemplatepackagemembership Object and children
 * @export
 */
/*export type EzsigntemplatepackagemembershipRequestCompound = EzsigntemplatepackagemembershipRequest;*/
export interface EzsigntemplatepackagemembershipRequestCompound {
    /**
     * The unique ID of the Ezsigntemplatepackagemembership
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequestCompound
     */
    pkiEzsigntemplatepackagemembershipID?:number 
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequestCompound
     */
    fkiEzsigntemplatepackageID:number 
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequestCompound
     */
    fkiEzsigntemplateID:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagemembershipRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagemembershipRequestCompound
 */
export class DataObjectEzsigntemplatepackagemembershipRequestCompound {
    pkiEzsigntemplatepackagemembershipID?:number = undefined
    fkiEzsigntemplatepackageID:number = 0
    fkiEzsigntemplateID:number = 0
}

/**
 * @export 
 * A EzsigntemplatepackagemembershipRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackagemembershipRequestCompound
 */
export class ValidationObjectEzsigntemplatepackagemembershipRequestCompound {
   pkiEzsigntemplatepackagemembershipID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
} 


