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
import type { EzsignfoldertypeRequestV3 } from './ezsignfoldertype-request-v3';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeCompletion } from './field-eezsignfoldertype-completion';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeDisposal } from './field-eezsignfoldertype-disposal';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeDocumentdependency } from './field-eezsignfoldertype-documentdependency';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePdfanoncompliantaction } from './field-eezsignfoldertype-pdfanoncompliantaction';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePdfarequirement } from './field-eezsignfoldertype-pdfarequirement';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignfoldertypeSigneraccess } from './field-eezsignfoldertype-signeraccess';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzsignfoldertypeName } from './multilingual-ezsignfoldertype-name';

/**
 * @type EzsignfoldertypeRequestCompoundV3
 * A Ezsignfoldertype Object and children
 * @export
 */
/*export type EzsignfoldertypeRequestCompoundV3 = EzsignfoldertypeRequestV3;*/
export interface EzsignfoldertypeRequestCompoundV3 {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestCompoundV3
     */
    a_fkiUserIDSigned?:Array<number> 
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestCompoundV3
     */
    a_fkiUserIDSummary?:Array<number> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldertypeRequestCompoundV3 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeRequestCompoundV3
 */
export class DataObjectEzsignfoldertypeRequestCompoundV3 {
    a_fkiUserIDSigned?:Array<number> = undefined
    a_fkiUserIDSummary?:Array<number> = undefined
}

/**
 * @export 
 * A EzsignfoldertypeRequestCompoundV3 Validation Object
 * @class ValidationObjectEzsignfoldertypeRequestCompoundV3
 */
export class ValidationObjectEzsignfoldertypeRequestCompoundV3 {
   a_fkiUserIDSigned = {
      type: 'array',
      required: false
   }
   a_fkiUserIDSummary = {
      type: 'array',
      required: false
   }
} 


