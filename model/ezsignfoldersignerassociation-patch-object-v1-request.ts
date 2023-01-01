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
import { EzsignfoldersignerassociationRequestPatch } from './ezsignfoldersignerassociation-request-patch';

import { DefaultObject } from '../base'

/**
 * Request for PATCH /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 * @interface EzsignfoldersignerassociationPatchObjectV1Request
 */
export interface EzsignfoldersignerassociationPatchObjectV1Request {
    /**
     * 
     * @type {EzsignfoldersignerassociationRequestPatch}
     * @memberof EzsignfoldersignerassociationPatchObjectV1Request
     */
    'objEzsignfoldersignerassociation': EzsignfoldersignerassociationRequestPatch;
}
/**
 * A EzsignfoldersignerassociationPatchObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationPatchObjectV1Request
 */
export class DefaultObjectEzsignfoldersignerassociationPatchObjectV1Request extends DefaultObject {
   objEzsignfoldersignerassociation:Partial<EzsignfoldersignerassociationRequestPatch> = {}
}


