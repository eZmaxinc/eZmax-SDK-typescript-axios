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
import { EzsignfoldersignerassociationGetObjectV1ResponseMPayload } from './ezsignfoldersignerassociation-get-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfoldersignerassociationGetObjectV1ResponseAllOf
 */
export interface EzsignfoldersignerassociationGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfoldersignerassociationGetObjectV1ResponseMPayload}
     * @memberof EzsignfoldersignerassociationGetObjectV1ResponseAllOf
     */
    'mPayload': EzsignfoldersignerassociationGetObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationGetObjectV1ResponseAllOf
 */
export class DataObjectEzsignfoldersignerassociationGetObjectV1ResponseAllOf {
   mPayload:EzsignfoldersignerassociationGetObjectV1ResponseMPayload = new DataObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationGetObjectV1ResponseAllOf
 */
export class ValidationObjectEzsignfoldersignerassociationGetObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload()
} 


