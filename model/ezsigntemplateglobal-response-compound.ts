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
import type { EzsigntemplateglobalResponse } from './ezsigntemplateglobal-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateglobaldocumentResponse } from './ezsigntemplateglobaldocument-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateglobalsignerResponseCompound } from './ezsigntemplateglobalsigner-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateglobalModule } from './field-eezsigntemplateglobal-module';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateglobalSupplier } from './field-eezsigntemplateglobal-supplier';

/**
 * @type EzsigntemplateglobalResponseCompound
 * A Ezsigntemplateglobal Object
 * @export
 */
/*export type EzsigntemplateglobalResponseCompound = EzsigntemplateglobalResponse;*/
export interface EzsigntemplateglobalResponseCompound {
    /**
     * 
     * @type {EzsigntemplateglobaldocumentResponse}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    objEzsigntemplateglobaldocument?:EzsigntemplateglobaldocumentResponse 
    /**
     * 
     * @type {Array<EzsigntemplateglobalsignerResponseCompound>}
     * @memberof EzsigntemplateglobalResponseCompound
     */
    a_objEzsigntemplateglobalsigner:Array<EzsigntemplateglobalsignerResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateglobaldocumentResponse } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateglobaldocumentResponse } from './'

/**
 * @export 
 * A EzsigntemplateglobalResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateglobalResponseCompound
 */
export class DataObjectEzsigntemplateglobalResponseCompound {
    objEzsigntemplateglobaldocument?:EzsigntemplateglobaldocumentResponse = undefined
    a_objEzsigntemplateglobalsigner:Array<EzsigntemplateglobalsignerResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplateglobalResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplateglobalResponseCompound
 */
export class ValidationObjectEzsigntemplateglobalResponseCompound {
   objEzsigntemplateglobaldocument = new ValidationObjectEzsigntemplateglobaldocumentResponse()
   a_objEzsigntemplateglobalsigner = {
      type: 'array',
      required: true
   }
} 


