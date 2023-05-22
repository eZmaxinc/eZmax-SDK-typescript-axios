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
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipResponse } from './ezsigntemplatepackagemembership-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipResponseCompoundAllOf } from './ezsigntemplatepackagemembership-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

/**
 * @type EzsigntemplatepackagemembershipResponseCompound
 * A Ezsigntemplatepackagemembership Object
 * @export
 */
export type EzsigntemplatepackagemembershipResponseCompound = EzsigntemplatepackagemembershipResponse & EzsigntemplatepackagemembershipResponseCompoundAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateResponseCompound } from './'

/**
 * @export 
 * A EzsigntemplatepackagemembershipResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagemembershipResponseCompound
 */
export class DataObjectEzsigntemplatepackagemembershipResponseCompound {
   pkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   fkiEzsigntemplateID:number = 0
   iEzsigntemplatepackagemembershipOrder:number = 0
   objEzsigntemplate:EzsigntemplateResponseCompound = new DataObjectEzsigntemplateResponseCompound()
   a_objEzsigntemplatepackagesignermembership:Array<EzsigntemplatepackagesignermembershipResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplatepackagemembershipResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackagemembershipResponseCompound
 */
export class ValidationObjectEzsigntemplatepackagemembershipResponseCompound {
   pkiEzsigntemplatepackagemembershipID = {
      type: 'integer',
      minimum: 0,
      required: true
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
   iEzsigntemplatepackagemembershipOrder = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   objEzsigntemplate = new ValidationObjectEzsigntemplateResponseCompound()
   a_objEzsigntemplatepackagesignermembership = {
      type: 'array',
      required: true
   }
} 


