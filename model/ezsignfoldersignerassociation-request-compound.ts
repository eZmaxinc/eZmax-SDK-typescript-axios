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
import type { EzsignfoldersignerassociationRequest } from './ezsignfoldersignerassociation-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignerRequestCompound } from './ezsignsigner-request-compound';

/**
 * @type EzsignfoldersignerassociationRequestCompound
 * An Ezsignfoldersignerassociation Object and children to create a complete structure
 * @export
 */
/*export type EzsignfoldersignerassociationRequestCompound = EzsignfoldersignerassociationRequest;*/
export interface EzsignfoldersignerassociationRequestCompound {
    /**
     * 
     * @type {EzsignsignerRequestCompound}
     * @memberof EzsignfoldersignerassociationRequestCompound
     */
    objEzsignsigner?:EzsignsignerRequestCompound 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignerRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignsignerRequestCompound } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationRequestCompound
 */
export class DataObjectEzsignfoldersignerassociationRequestCompound {
    objEzsignsigner?:EzsignsignerRequestCompound = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationRequestCompound Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationRequestCompound
 */
export class ValidationObjectEzsignfoldersignerassociationRequestCompound {
   objEzsignsigner = new ValidationObjectEzsignsignerRequestCompound()
} 


