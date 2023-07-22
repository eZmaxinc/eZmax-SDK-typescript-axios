/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipResponse } from './ezsigntemplatepackagesignermembership-response';

/**
 * @type EzsigntemplatepackagesignermembershipResponseCompound
 * A Ezsigntemplatepackagesignermembership Object
 * @export
 */
export type EzsigntemplatepackagesignermembershipResponseCompound = EzsigntemplatepackagesignermembershipResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipResponseCompound
 */
export class DataObjectEzsigntemplatepackagesignermembershipResponseCompound {
    pkiEzsigntemplatepackagesignermembershipID:number = 0
    fkiEzsigntemplatepackagemembershipID:number = 0
    fkiEzsigntemplatepackagesignerID:number = 0
    fkiEzsigntemplatesignerID:number = 0
    iEzsigntemplatepackagesignermembershipCopy?:number = undefined
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipResponseCompound
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipResponseCompound {
   pkiEzsigntemplatepackagesignermembershipID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatepackagemembershipID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatepackagesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatepackagesignermembershipCopy = {
      type: 'integer',
      minimum: 1,
      required: false
   }
} 


