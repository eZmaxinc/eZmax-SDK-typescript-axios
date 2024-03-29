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
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

/**
 * 
 * @export
 * @interface EzsigntemplatepackagemembershipResponseCompoundAllOf
 */
export interface EzsigntemplatepackagemembershipResponseCompoundAllOf {
    /**
     * 
     * @type {EzsigntemplateResponseCompound}
     * @memberof EzsigntemplatepackagemembershipResponseCompoundAllOf
     */
    'objEzsigntemplate': EzsigntemplateResponseCompound;
    /**
     * 
     * @type {Array<EzsigntemplatepackagesignermembershipResponseCompound>}
     * @memberof EzsigntemplatepackagemembershipResponseCompoundAllOf
     */
    'a_objEzsigntemplatepackagesignermembership': Array<EzsigntemplatepackagesignermembershipResponseCompound>;
}
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
 * A EzsigntemplatepackagemembershipResponseCompoundAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagemembershipResponseCompoundAllOf
 */
export class DataObjectEzsigntemplatepackagemembershipResponseCompoundAllOf {
   objEzsigntemplate:EzsigntemplateResponseCompound = new DataObjectEzsigntemplateResponseCompound()
   a_objEzsigntemplatepackagesignermembership:Array<EzsigntemplatepackagesignermembershipResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplatepackagemembershipResponseCompoundAllOf Validation Object
 * @class ValidationObjectEzsigntemplatepackagemembershipResponseCompoundAllOf
 */
export class ValidationObjectEzsigntemplatepackagemembershipResponseCompoundAllOf {
   objEzsigntemplate = new ValidationObjectEzsigntemplateResponseCompound()
   a_objEzsigntemplatepackagesignermembership = {
      type: 'array',
      required: true
   }
} 


